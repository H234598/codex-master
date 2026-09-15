from __future__ import annotations

from dataclasses import FrozenInstanceError
from importlib import import_module
from pathlib import Path

import pytest

from the_hive.hive.bus_types import (
    EVENT_TYPE_MATRIX,
    BusSubscriptionSetV1,
    HiveBusContractError,
    HiveBusEventV1,
    canonical_json_bytes,
    create_hive_bus_event_v1,
    event_id_for_publish_request,
    event_type_spec,
    partition_kind,
    serialize_bus_subscription_set_v1,
    serialize_hive_bus_event_v1,
    validate_event_type_producer_partition,
    validate_topic_partition,
)


IDEMPOTENCY_KEY = "idempotency-v1-0123456789abcdef0123456789abcdef"
PRODUCER_PRINCIPAL_ID = "producer-principal-v1-0123456789abcdef0123456789abcdef"
PRODUCER_SESSION_ID = "producer-session-v1-0123456789abcdef0123456789abcdef"
CORRELATION_ID = "correlation-v1-0123456789abcdef0123456789abcdef"
AUTHORITY_GRANT_ID = "authority-grant-v1-0123456789abcdef0123456789abcdef"


def _digest(character: str = "a") -> str:
    return "sha256:" + (character * 64)


def _publish_request() -> dict[str, object]:
    return {
        "schema_version": 1,
        "event_type": "assignment.created",
        "partition": "repo/repo-1/task/task-1",
        "idempotency_key": IDEMPOTENCY_KEY,
        "producer_principal_id": PRODUCER_PRINCIPAL_ID,
        "producer_session_id": PRODUCER_SESSION_ID,
        "producer_epoch": 1,
        "producer_seq": 1,
        "repo_id": "repo-1",
        "topic_id": None,
        "workpackage_id": "task-1",
        "correlation_id": CORRELATION_ID,
        "causation_ids": [],
        "authority": {
            "grant_id": AUTHORITY_GRANT_ID,
            "scope_digest": _digest("b"),
            "principal_version": 1,
        },
        "classification": "internal",
        "payload": {
            "kind": "inline",
            "digest": _digest("c"),
            "ref": "inline:" + _digest("c"),
            "size_bytes": 64,
        },
        "retention_class": "work",
        "created_at_utc": "2026-09-04T12:30:45.120000Z",
    }


def _build_event(request: dict[str, object] | None = None) -> HiveBusEventV1:
    return create_hive_bus_event_v1(
        _publish_request() if request is None else request,
        partition_seq=1,
        accepted_at_utc="2026-09-04T12:31:00Z",
    )


def _oversized_publish_request() -> dict[str, object]:
    """A former arbitrary-header overrun is now a closed-ID schema violation."""

    return _publish_request() | {"idempotency_key": "a" * 512}


def _result_proposed_request() -> dict[str, object]:
    payload = _publish_request()["payload"]
    assert isinstance(payload, dict)
    return _publish_request() | {
        "event_type": "result.proposed",
        "idempotency_key": "idempotency-v1-11111111111111111111111111111111",
        "producer_epoch": 2,
        "producer_seq": 9,
        "correlation_id": "correlation-v1-11111111111111111111111111111111",
        "payload": payload
        | {"kind": "blob", "ref": "blob:" + _digest("c"), "size_bytes": 4096},
    }


def _policy_invalidated_request() -> dict[str, object]:
    return _publish_request() | {
        "event_type": "policy.invalidated",
        "partition": "policy/policy-1",
        "idempotency_key": "idempotency-v1-22222222222222222222222222222222",
        "producer_principal_id": "producer-principal-v1-22222222222222222222222222222222",
        "producer_session_id": "producer-session-v1-22222222222222222222222222222222",
        "repo_id": None,
        "workpackage_id": None,
        "correlation_id": "correlation-v1-22222222222222222222222222222222",
        "retention_class": "audit",
        "created_at_utc": "2026-09-04T13:00:00Z",
    }


def _scope_request(
    *,
    event_type: str,
    partition: str,
    repo_id: str | None,
    topic_id: str | None,
    workpackage_id: str | None,
    retention_class: str,
    payload_kind: str = "inline",
) -> dict[str, object]:
    payload = _publish_request()["payload"]
    assert isinstance(payload, dict)
    payload_ref = f"{payload_kind}:{_digest('c')}"
    if payload_kind == "artifact":
        payload_ref = f"artifact:artifact-1@{_digest('c')}"
    return _publish_request() | {
        "event_type": event_type,
        "partition": partition,
        "repo_id": repo_id,
        "topic_id": topic_id,
        "workpackage_id": workpackage_id,
        "retention_class": retention_class,
        "payload": payload | {"kind": payload_kind, "ref": payload_ref},
    }


def test_topic_grammar_is_bounded_and_partition_kinds_are_closed() -> None:
    assert (
        validate_topic_partition("repo/repo-1/topic/topic-1")
        == "repo/repo-1/topic/topic-1"
    )
    assert partition_kind("repo/repo-1/task/task-1") == "task"
    assert partition_kind("security/global") == "security_global"

    for unsafe in (
        "repo//topic",
        "repo/repo-1/topic/..",
        "repo/repo-1/topic/*",
        "repo/repo-1/topic/topic-1/",
        "repo/repo-1/topic/Topic-1",
        "repo/" + ("a" * 65),
        "repo/repo-1/topic/\x00",
        "repo/repo-1/topic/" + ("a" * 500),
        "provider/provider-1/usage",
    ):
        with pytest.raises(HiveBusContractError, match="BUS_E_TOPIC_INVALID"):
            validate_topic_partition(unsafe)


@pytest.mark.parametrize(
    "unsafe",
    ("api.key.value", "API:KEY:VALUE", "secret-segment", "SeCrEt_Segment"),
)
@pytest.mark.parametrize(
    "partition_template",
    (
        "repo/{unsafe}",
        "repo/repo-1/topic/{unsafe}",
        "repo/repo-1/task/{unsafe}",
        "repo/repo-1/artifact/{unsafe}",
        "archive/repo/{unsafe}",
        "fleet/resource/{unsafe}",
        "provider/{unsafe}/status",
        "account/{unsafe}/usage",
        "policy/{unsafe}",
        "security/repo/{unsafe}",
        "incident/{unsafe}",
        "coordination/repo/{unsafe}/to/repo-2",
        "coordination/repo/repo-1/to/{unsafe}",
        "user/notification/{unsafe}",
    ),
)
def test_every_partition_segment_rejects_sensitive_markers(
    unsafe: str, partition_template: str
) -> None:
    with pytest.raises(HiveBusContractError, match="BUS_E_SECRET_CLASSIFICATION"):
        validate_topic_partition(partition_template.format(unsafe=unsafe))


@pytest.mark.parametrize(
    "unsafe",
    ("api.key.value", "API:KEY:VALUE", "secret-segment", "SeCrEt_Segment"),
)
@pytest.mark.parametrize(
    "field",
    (
        "repo_id",
        "topic_id",
        "workpackage_id",
    ),
)
def test_scope_identifiers_reject_sensitive_marker_bypasses(
    field: str, unsafe: str
) -> None:
    with pytest.raises(HiveBusContractError, match="BUS_E_SECRET_CLASSIFICATION"):
        _build_event(_publish_request() | {field: unsafe})


@pytest.mark.parametrize(
    ("field", "identifier"),
    (
        ("idempotency_key", IDEMPOTENCY_KEY),
        ("producer_principal_id", PRODUCER_PRINCIPAL_ID),
        ("producer_session_id", PRODUCER_SESSION_ID),
        ("correlation_id", CORRELATION_ID),
    ),
)
def test_generated_header_identifier_namespaces_accept_only_their_exact_form(
    field: str, identifier: str
) -> None:
    event = _build_event(_publish_request() | {field: identifier})
    assert getattr(event, field) == identifier


@pytest.mark.parametrize(
    "field",
    (
        "idempotency_key",
        "producer_principal_id",
        "producer_session_id",
        "correlation_id",
    ),
)
@pytest.mark.parametrize(
    "unsafe",
    (
        "ghp_0123456789abcdef0123456789abcdef0123",
        "github_pat_0123456789abcdef0123456789abcdef",
        "sk-0123456789abcdef0123456789abcdef",
        "AIza0123456789abcdef0123456789abcdef",
        "xox-0123456789abcdef0123456789abcdef",
        "bearer-0123456789abcdef0123456789abcdef",
        "token-0123456789abcdef0123456789abcdef",
        "auth-0123456789abcdef0123456789abcdef",
        "arbitrary-opaque-value",
    ),
)
def test_generated_header_identifier_namespaces_reject_credentials_and_opaque_values(
    field: str, unsafe: str
) -> None:
    with pytest.raises(HiveBusContractError, match="BUS_E_SCHEMA"):
        _build_event(_publish_request() | {field: unsafe})


@pytest.mark.parametrize(
    "unsafe",
    (
        "authority-grant-v1-0123456789abcdef0123456789abcde",
        "grant-v1-0123456789abcdef0123456789abcdef",
        "ghp_0123456789abcdef0123456789abcdef0123",
        "github_pat_0123456789abcdef0123456789abcdef",
        "sk-0123456789abcdef0123456789abcdef",
        "AIza0123456789abcdef0123456789abcdef",
        "xox-0123456789abcdef0123456789abcdef",
        "bearer-0123456789abcdef0123456789abcdef",
        "token-0123456789abcdef0123456789abcdef",
        "auth-0123456789abcdef0123456789abcdef",
        "arbitrary-opaque-value",
    ),
)
def test_authority_grant_identifier_rejects_non_generated_values(unsafe: str) -> None:
    authority = _publish_request()["authority"]
    assert isinstance(authority, dict)
    with pytest.raises(HiveBusContractError, match="BUS_E_SCHEMA"):
        _build_event(
            _publish_request() | {"authority": authority | {"grant_id": unsafe}}
        )


def test_authority_grant_identifier_accepts_its_exact_generated_form() -> None:
    authority = _publish_request()["authority"]
    assert isinstance(authority, dict)

    event = _build_event(
        _publish_request() | {"authority": authority | {"grant_id": AUTHORITY_GRANT_ID}}
    )

    assert event.authority.grant_id == AUTHORITY_GRANT_ID


@pytest.mark.parametrize(
    (
        "event_type",
        "partition",
        "repo_id",
        "topic_id",
        "workpackage_id",
        "retention_class",
        "payload_kind",
    ),
    (
        ("decision.changed", "repo/repo-1", "repo-1", None, None, "audit", "inline"),
        (
            "decision.changed",
            "repo/repo-1/topic/topic-1",
            "repo-1",
            "topic-1",
            None,
            "audit",
            "inline",
        ),
        (
            "assignment.created",
            "repo/repo-1/task/task-1",
            "repo-1",
            None,
            "task-1",
            "work",
            "inline",
        ),
        (
            "artifact.accepted",
            "repo/repo-1/artifact/artifact-1",
            "repo-1",
            None,
            None,
            "audit",
            "artifact",
        ),
        (
            "artifact.archived",
            "archive/repo/repo-1",
            "repo-1",
            None,
            None,
            "audit",
            "artifact",
        ),
        ("authority.revoked", "fleet/control", None, None, None, "audit", "inline"),
        (
            "resource.emergency",
            "fleet/resource/cpu",
            None,
            None,
            None,
            "transient",
            "inline",
        ),
        (
            "provider.hard_stopped",
            "provider/provider-1/status",
            None,
            None,
            None,
            "transient",
            "inline",
        ),
        (
            "digest.tick",
            "account/account-1/usage",
            None,
            None,
            None,
            "transient",
            "inline",
        ),
        (
            "policy.invalidated",
            "policy/policy-1",
            None,
            None,
            None,
            "audit",
            "inline",
        ),
        (
            "security.critical",
            "security/repo/repo-1",
            "repo-1",
            None,
            None,
            "audit",
            "inline",
        ),
        (
            "security.critical",
            "security/global",
            None,
            None,
            None,
            "audit",
            "inline",
        ),
        ("digest.tick", "incident/incident-1", None, None, None, "transient", "inline"),
        (
            "decision.changed",
            "coordination/repo/repo-1/to/repo-2",
            "repo-1",
            None,
            None,
            "audit",
            "inline",
        ),
        (
            "user.notification.requested",
            "user/notification/client-1",
            None,
            None,
            None,
            "transient",
            "inline",
        ),
    ),
)
def test_scope_metadata_is_exactly_bound_to_every_partition_family(
    event_type: str,
    partition: str,
    repo_id: str | None,
    topic_id: str | None,
    workpackage_id: str | None,
    retention_class: str,
    payload_kind: str,
) -> None:
    request = _scope_request(
        event_type=event_type,
        partition=partition,
        repo_id=repo_id,
        topic_id=topic_id,
        workpackage_id=workpackage_id,
        retention_class=retention_class,
        payload_kind=payload_kind,
    )
    event = _build_event(request)
    assert (event.repo_id, event.topic_id, event.workpackage_id) == (
        repo_id,
        topic_id,
        workpackage_id,
    )

    contradictory_scope = {
        "repo_id": "repo-2" if repo_id is not None else "repo-1",
        "topic_id": "topic-2" if topic_id is not None else "topic-1",
        "workpackage_id": "task-2" if workpackage_id is not None else "task-1",
    }
    for field, value in contradictory_scope.items():
        with pytest.raises(HiveBusContractError, match="BUS_E_REPO_SCOPE"):
            _build_event(request | {field: value})


def test_canonical_json_normalizes_nfc_and_rejects_noncanonical_json_shapes() -> None:
    assert canonical_json_bytes({"z": 1, "a": "cafe\u0301"}) == (
        b'{"a":"caf\xc3\xa9","z":1}'
    )

    too_deep: object = "leaf"
    for _ in range(9):
        too_deep = [too_deep]

    for invalid in (
        {True: 1},
        {"number": 1.0},
        {"control": "unsafe\nvalue"},
        {"surrogate": "\ud800"},
        too_deep,
        {f"item-{index}": index for index in range(129)},
    ):
        with pytest.raises(HiveBusContractError, match="BUS_E_CANONICALIZATION"):
            canonical_json_bytes(invalid)


def test_event_is_immutable_canonical_and_uses_stable_gold_event_id() -> None:
    request = _publish_request()
    event = _build_event(request)
    retried = create_hive_bus_event_v1(
        dict(reversed(list(request.items()))),
        partition_seq=99,
        accepted_at_utc="2026-09-04T12:32:00.000000Z",
    )

    assert event.created_at_utc == "2026-09-04T12:30:45.12Z"
    assert (
        event.event_id
        == "sha256:b6ca9f3afec45a6ce28be14ed6e86e44502cbe60a6a3dc264571a2adef4d3cba"
    )
    assert event_id_for_publish_request(request) == event.event_id
    assert retried.event_id == event.event_id
    assert retried.partition_seq == 99
    assert event.raw_output == "not_returned"
    assert serialize_hive_bus_event_v1(event) == {
        **_publish_request(),
        "created_at_utc": "2026-09-04T12:30:45.12Z",
        "partition_seq": 1,
        "event_id": event.event_id,
        "accepted_at_utc": "2026-09-04T12:31:00Z",
        "raw_output": "not_returned",
    }

    with pytest.raises(FrozenInstanceError):
        event.event_id = _digest("f")  # type: ignore[misc]
    with pytest.raises(TypeError):
        HiveBusEventV1()


@pytest.mark.parametrize(
    ("publish_request", "expected_event_id"),
    (
        (
            _result_proposed_request(),
            "sha256:f88eedf69aadf3a575217cc8e6c24b3093d1fd9515119b81f3fe204da521b55f",
        ),
        (
            _policy_invalidated_request(),
            "sha256:d4fc307b207570a2d806c0e8460735a7113b3d92e099ffaa330d430665a435be",
        ),
    ),
)
def test_event_id_has_multiple_deterministic_gold_vectors(
    publish_request: dict[str, object], expected_event_id: str
) -> None:
    event = _build_event(publish_request)

    assert event.event_id == expected_event_id
    assert (
        event_id_for_publish_request(dict(reversed(list(publish_request.items()))))
        == expected_event_id
    )


def test_event_type_matrix_encodes_producer_class_partition_pairs() -> None:
    coordination = "coordination/repo/repo-1/to/repo-2"
    assert (
        validate_event_type_producer_partition(
            "handoff.available", "queen", coordination
        )
        == "coordination"
    )
    assert (
        validate_event_type_producer_partition(
            "coordination.attention_requested", "teamlead", "repo/repo-1"
        )
        == "repo"
    )

    for event_type, producer_class, partition in (
        ("handoff.available", "teamlead", coordination),
        ("handoff.available", "worker", coordination),
        ("handoff.available", "specialist", coordination),
        ("handoff.available", "topic_queen", coordination),
        ("coordination.attention_requested", "teamlead", coordination),
        ("coordination.attention_requested", "teamlead", "repo/repo-1/task/task-1"),
        ("coordination.attention_requested", "queen", "repo/repo-1"),
        ("result.proposed", "worker", coordination),
        ("policy.invalidated", "queen", "policy/policy-1"),
        ("provider.hard_stopped", "queen", "provider/provider-1/status"),
        ("resource.emergency", "queen", "fleet/resource/cpu"),
        ("artifact.accepted", "godbee", "repo/repo-1/artifact/artifact-1"),
        ("assignment.created", "godbee", "repo/repo-1/task/task-1"),
        ("blocker.encountered", "godbee", "repo/repo-1/topic/topic-1"),
        ("session.sleep_requested", "godbee", "repo/repo-1/task/task-1"),
        ("artifact.ready", "worker", "repo/repo-1/artifact/artifact-1"),
    ):
        with pytest.raises(HiveBusContractError, match="BUS_E_ACL_DENIED"):
            validate_event_type_producer_partition(
                event_type, producer_class, partition
            )

    cross_repo_pairs = {
        (event_type, producer_class)
        for event_type, spec in EVENT_TYPE_MATRIX.items()
        for producer_class, partition_kind_value in spec.producer_partition_pairs
        if partition_kind_value == "coordination"
    }
    assert cross_repo_pairs == {
        ("blocker.encountered", "queen"),
        ("decision.changed", "queen"),
        ("handoff.available", "queen"),
        ("interface.changed", "queen"),
        ("scope.affected", "queen"),
    }


def test_skill_requested_is_a_nonurgent_inline_worker_task_request() -> None:
    """A role or payload widening here would bypass the typed worker request path."""

    spec = event_type_spec("skill.requested")

    assert spec.producer_partition_pairs == frozenset(
        {
            ("worker", "task"),
            ("specialist", "task"),
        }
    )
    assert spec.payload_kinds == frozenset({"inline"})
    assert spec.retention_class == "work"
    assert spec.urgent is False
    assert (
        validate_event_type_producer_partition(
            "skill.requested", "worker", "repo/repo-1/task/task-1"
        )
        == "task"
    )

    for producer_class in ("teamlead", "queen", "godbee"):
        with pytest.raises(HiveBusContractError, match="BUS_E_ACL_DENIED"):
            validate_event_type_producer_partition(
                "skill.requested", producer_class, "repo/repo-1/task/task-1"
            )


def test_event_type_matrix_is_the_complete_role_partition_contract() -> None:
    """An accidental pair addition must not widen a producer's BUS-S0 role."""

    actual = {
        event_type: (
            spec.producer_partition_pairs,
            spec.payload_kinds,
            spec.retention_class,
            spec.urgent,
        )
        for event_type, spec in EVENT_TYPE_MATRIX.items()
    }

    assert actual == {
        "archive.evidence_missing": (
            frozenset({("archivist", "archive")}),
            frozenset({"inline"}),
            "audit",
            False,
        ),
        "artifact.accepted": (
            frozenset({("queen", "artifact"), ("topic_queen", "artifact")}),
            frozenset({"artifact"}),
            "audit",
            True,
        ),
        "artifact.archived": (
            frozenset({("archivist", "archive"), ("archivist", "artifact")}),
            frozenset({"artifact"}),
            "audit",
            False,
        ),
        "artifact.ready": (
            frozenset({("specialist", "task"), ("worker", "task")}),
            frozenset({"artifact"}),
            "work",
            False,
        ),
        "assignment.cancelled": (
            frozenset(
                {
                    ("queen", "task"),
                    ("teamlead", "task"),
                    ("topic_queen", "task"),
                }
            ),
            frozenset({"inline"}),
            "work",
            True,
        ),
        "assignment.created": (
            frozenset(
                {
                    ("queen", "task"),
                    ("teamlead", "task"),
                    ("topic_queen", "task"),
                }
            ),
            frozenset({"inline"}),
            "work",
            False,
        ),
        "assignment.started": (
            frozenset(
                {
                    ("specialist", "task"),
                    ("teamlead", "task"),
                    ("worker", "task"),
                }
            ),
            frozenset({"inline"}),
            "work",
            False,
        ),
        "authority.revoked": (
            frozenset(
                {
                    ("broker", "fleet_control"),
                    ("broker", "policy"),
                    ("broker", "security_global"),
                    ("broker", "security_repo"),
                    ("godbee", "fleet_control"),
                    ("godbee", "policy"),
                    ("godbee", "security_global"),
                    ("queen", "artifact"),
                    ("queen", "repo"),
                    ("queen", "security_repo"),
                    ("queen", "task"),
                    ("queen", "topic"),
                }
            ),
            frozenset({"inline"}),
            "audit",
            True,
        ),
        "blocker.detected": (
            frozenset({("specialist", "task"), ("worker", "task")}),
            frozenset({"inline"}),
            "work",
            False,
        ),
        "blocker.encountered": (
            frozenset(
                {
                    ("queen", "coordination"),
                    ("queen", "repo"),
                    ("queen", "task"),
                    ("queen", "topic"),
                    ("specialist", "task"),
                    ("teamlead", "repo"),
                    ("teamlead", "task"),
                    ("teamlead", "topic"),
                    ("topic_queen", "task"),
                    ("topic_queen", "topic"),
                    ("worker", "task"),
                }
            ),
            frozenset({"inline"}),
            "work",
            False,
        ),
        "bus.gemini_cooldown_notice_pending": (
            frozenset({("broker", "fleet_control"), ("teamlead", "task")}),
            frozenset({"inline"}),
            "work",
            False,
        ),
        "coordination.attention_requested": (
            frozenset({("teamlead", "repo")}),
            frozenset({"inline"}),
            "work",
            False,
        ),
        "decision.changed": (
            frozenset(
                {
                    ("godbee", "policy"),
                    ("queen", "coordination"),
                    ("queen", "repo"),
                    ("queen", "task"),
                    ("queen", "topic"),
                    ("teamlead", "repo"),
                    ("teamlead", "task"),
                    ("teamlead", "topic"),
                    ("topic_queen", "task"),
                    ("topic_queen", "topic"),
                }
            ),
            frozenset({"inline"}),
            "audit",
            False,
        ),
        "dependency.requested": (
            frozenset({("specialist", "task"), ("worker", "task")}),
            frozenset({"inline"}),
            "work",
            False,
        ),
        "dependency.satisfied": (
            frozenset({("specialist", "task"), ("worker", "task")}),
            frozenset({"inline"}),
            "work",
            False,
        ),
        "digest.tick": (
            frozenset(
                {
                    ("broker", "account_usage"),
                    ("broker", "archive"),
                    ("broker", "artifact"),
                    ("broker", "fleet_control"),
                    ("broker", "fleet_resource"),
                    ("broker", "incident"),
                    ("broker", "notification"),
                    ("broker", "policy"),
                    ("broker", "provider_status"),
                    ("broker", "repo"),
                    ("broker", "security_global"),
                    ("broker", "security_repo"),
                    ("broker", "task"),
                    ("broker", "topic"),
                }
            ),
            frozenset({"inline"}),
            "transient",
            False,
        ),
        "gemini.cooldown.committed.v1": (
            frozenset(
                {
                    ("specialist", "task"),
                    ("teamlead", "task"),
                    ("worker", "task"),
                }
            ),
            frozenset({"inline"}),
            "work",
            False,
        ),
        "handoff.available": (
            frozenset(
                {
                    ("godbee", "repo"),
                    ("queen", "coordination"),
                    ("queen", "repo"),
                    ("queen", "task"),
                    ("queen", "topic"),
                    ("teamlead", "repo"),
                    ("teamlead", "task"),
                    ("teamlead", "topic"),
                    ("topic_queen", "task"),
                    ("topic_queen", "topic"),
                }
            ),
            frozenset({"inline"}),
            "work",
            False,
        ),
        "interface.changed": (
            frozenset(
                {
                    ("queen", "coordination"),
                    ("queen", "repo"),
                    ("queen", "task"),
                    ("queen", "topic"),
                    ("specialist", "task"),
                    ("teamlead", "repo"),
                    ("teamlead", "task"),
                    ("teamlead", "topic"),
                    ("topic_queen", "task"),
                    ("topic_queen", "topic"),
                    ("worker", "task"),
                }
            ),
            frozenset({"inline"}),
            "work",
            False,
        ),
        "policy.invalidated": (
            frozenset(
                {
                    ("broker", "fleet_control"),
                    ("broker", "policy"),
                    ("godbee", "policy"),
                }
            ),
            frozenset({"inline"}),
            "audit",
            True,
        ),
        "provider.hard_stopped": (
            frozenset({("broker", "provider_status")}),
            frozenset({"inline"}),
            "transient",
            True,
        ),
        "resource.emergency": (
            frozenset({("broker", "fleet_resource")}),
            frozenset({"inline"}),
            "transient",
            True,
        ),
        "result.proposed": (
            frozenset({("specialist", "task"), ("worker", "task")}),
            frozenset({"artifact", "blob", "inline"}),
            "work",
            False,
        ),
        "result.report": (
            frozenset(
                {
                    ("specialist", "task"),
                    ("teamlead", "task"),
                    ("worker", "task"),
                }
            ),
            frozenset({"artifact", "blob", "inline"}),
            "work",
            False,
        ),
        "review.completed": (
            frozenset(
                {
                    ("queen", "task"),
                    ("teamlead", "task"),
                    ("topic_queen", "task"),
                }
            ),
            frozenset({"artifact", "blob", "inline"}),
            "work",
            False,
        ),
        "scope.affected": (
            frozenset(
                {
                    ("godbee", "policy"),
                    ("godbee", "repo"),
                    ("queen", "coordination"),
                    ("queen", "repo"),
                    ("queen", "task"),
                    ("queen", "topic"),
                    ("teamlead", "repo"),
                    ("teamlead", "task"),
                    ("teamlead", "topic"),
                    ("topic_queen", "task"),
                    ("topic_queen", "topic"),
                }
            ),
            frozenset({"inline"}),
            "audit",
            False,
        ),
        "security.critical": (
            frozenset(
                {
                    ("broker", "security_global"),
                    ("broker", "security_repo"),
                    ("godbee", "security_global"),
                    ("queen", "security_repo"),
                }
            ),
            frozenset({"inline"}),
            "audit",
            True,
        ),
        "session.sleep_requested": (
            frozenset(
                {
                    ("queen", "task"),
                    ("queen", "topic"),
                    ("teamlead", "task"),
                    ("teamlead", "topic"),
                    ("topic_queen", "task"),
                    ("topic_queen", "topic"),
                }
            ),
            frozenset({"inline"}),
            "work",
            True,
        ),
        "skill.requested": (
            frozenset({("specialist", "task"), ("worker", "task")}),
            frozenset({"inline"}),
            "work",
            False,
        ),
        "spawn.requested": (
            frozenset({("specialist", "task"), ("worker", "task")}),
            frozenset({"inline"}),
            "work",
            False,
        ),
        "test.result": (
            frozenset({("specialist", "task"), ("worker", "task")}),
            frozenset({"artifact", "blob", "inline"}),
            "work",
            False,
        ),
        "user.decision_recorded": (
            frozenset({("godbee", "policy"), ("godbee", "repo")}),
            frozenset({"inline"}),
            "audit",
            True,
        ),
        "user.notification.requested": (
            frozenset(
                {
                    ("broker", "notification"),
                    ("godbee", "notification"),
                    ("queen", "notification"),
                }
            ),
            frozenset({"inline"}),
            "transient",
            True,
        ),
    }


def test_event_type_matrix_covers_every_declared_bus_event_and_is_enforced() -> None:
    declared_event_types = frozenset(
        {
            "archive.evidence_missing",
            "artifact.accepted",
            "artifact.archived",
            "artifact.ready",
            "assignment.cancelled",
            "assignment.created",
            "assignment.started",
            "authority.revoked",
            "blocker.detected",
            "blocker.encountered",
            "bus.gemini_cooldown_notice_pending",
            "coordination.attention_requested",
            "decision.changed",
            "dependency.requested",
            "dependency.satisfied",
            "digest.tick",
            "gemini.cooldown.committed.v1",
            "handoff.available",
            "interface.changed",
            "policy.invalidated",
            "provider.hard_stopped",
            "resource.emergency",
            "result.proposed",
            "result.report",
            "review.completed",
            "scope.affected",
            "security.critical",
            "session.sleep_requested",
            "skill.requested",
            "spawn.requested",
            "test.result",
            "user.decision_recorded",
            "user.notification.requested",
        }
    )
    assert frozenset(EVENT_TYPE_MATRIX) == declared_event_types
    assert event_type_spec("artifact.accepted").retention_class == "audit"
    assert event_type_spec("authority.revoked").urgent is True

    with pytest.raises(HiveBusContractError, match="BUS_E_SCHEMA"):
        event_type_spec("chat.message")
    with pytest.raises(HiveBusContractError, match="BUS_E_SCHEMA"):
        _build_event(_publish_request() | {"event_type": "chat.message"})

    for spec in EVENT_TYPE_MATRIX.values():
        assert spec.event_type in declared_event_types
        assert spec.payload_kinds
        assert spec.partition_kinds
        assert spec.max_payload_bytes <= 1024 * 1024


def test_event_rejects_unknown_keys_caller_event_ids_and_non_integer_numbers() -> None:
    for key, value in (
        ("event_id", _digest("d")),
        ("partition_seq", 1),
        ("accepted_at_utc", "2026-09-04T12:31:00Z"),
        ("raw_output", "terminal output"),
        ("extra", "nope"),
    ):
        with pytest.raises(HiveBusContractError, match="BUS_E_SCHEMA"):
            _build_event(_publish_request() | {key: value})

    for field, value in (("producer_epoch", True), ("producer_seq", True)):
        with pytest.raises(HiveBusContractError, match="BUS_E_SCHEMA"):
            _build_event(_publish_request() | {field: value})

    with pytest.raises(HiveBusContractError, match="BUS_E_SCHEMA"):
        create_hive_bus_event_v1(
            _publish_request(),
            partition_seq=True,
            accepted_at_utc="2026-09-04T12:31:00Z",
        )

    authority = _publish_request()["authority"]
    assert isinstance(authority, dict)
    with pytest.raises(HiveBusContractError, match="BUS_E_SCHEMA"):
        _build_event(
            _publish_request() | {"authority": authority | {"principal_version": True}}
        )


def test_event_enforces_count_byte_payload_and_timestamp_bounds() -> None:
    causes = [_digest(format(index, "x")[-1]) for index in range(17)]
    with pytest.raises(HiveBusContractError, match="BUS_E_SCHEMA"):
        _build_event(_publish_request() | {"causation_ids": causes})

    inline_payload = _publish_request()["payload"]
    assert isinstance(inline_payload, dict)
    with pytest.raises(HiveBusContractError, match="BUS_E_EVENT_TOO_LARGE"):
        _build_event(
            _publish_request() | {"payload": inline_payload | {"size_bytes": 2049}}
        )

    blob_payload = inline_payload | {"kind": "blob", "size_bytes": 262_145}
    with pytest.raises(HiveBusContractError, match="BUS_E_EVENT_TOO_LARGE"):
        _build_event(
            _publish_request()
            | {"event_type": "result.proposed", "payload": blob_payload}
        )

    with pytest.raises(HiveBusContractError, match="BUS_E_SCHEMA"):
        _build_event(_oversized_publish_request())
    with pytest.raises(HiveBusContractError, match="BUS_E_SCHEMA"):
        event_id_for_publish_request(_oversized_publish_request())

    for timestamp in (
        "2026-09-04T12:30:45+00:00",
        "2026-09-04T12:30:45.1200000Z",
        "2026-09-04T12:61:00Z",
        "2026-09-04T12:30:45Z\n",
    ):
        with pytest.raises(HiveBusContractError, match="BUS_E_CANONICALIZATION"):
            _build_event(_publish_request() | {"created_at_utc": timestamp})


@pytest.mark.parametrize(
    ("event_type", "kind", "size_bytes", "accepted"),
    (
        ("assignment.created", "inline", 2 * 1024, True),
        ("assignment.created", "inline", (2 * 1024) + 1, False),
        ("result.proposed", "blob", 256 * 1024, True),
        ("result.proposed", "blob", (256 * 1024) + 1, False),
    ),
)
def test_inline_and_blob_payload_transport_limits_are_exact(
    event_type: str, kind: str, size_bytes: int, accepted: bool
) -> None:
    payload = _publish_request()["payload"]
    assert isinstance(payload, dict)
    request = _publish_request() | {
        "event_type": event_type,
        "payload": payload
        | {
            "kind": kind,
            "ref": f"{kind}:{_digest('c')}",
            "size_bytes": size_bytes,
        },
    }

    if accepted:
        assert _build_event(request).payload.size_bytes == size_bytes
    else:
        with pytest.raises(HiveBusContractError, match="BUS_E_EVENT_TOO_LARGE"):
            _build_event(request)


@pytest.mark.parametrize(
    "size_bytes",
    (
        256 * 1024,
        (256 * 1024) + 1,
        1024 * 1024,
        (1024 * 1024) + 1,
        (2**63) - 1,
    ),
)
def test_artifact_payload_size_is_bounded_metadata_not_transport_bytes(
    size_bytes: int,
) -> None:
    request = _scope_request(
        event_type="artifact.accepted",
        partition="repo/repo-1/artifact/artifact-1",
        repo_id="repo-1",
        topic_id=None,
        workpackage_id=None,
        retention_class="audit",
        payload_kind="artifact",
    )
    payload = request["payload"]
    assert isinstance(payload, dict)

    event = _build_event(request | {"payload": payload | {"size_bytes": size_bytes}})

    assert event.payload.size_bytes == size_bytes


def test_artifact_payload_metadata_bound_is_exact() -> None:
    request = _scope_request(
        event_type="artifact.accepted",
        partition="repo/repo-1/artifact/artifact-1",
        repo_id="repo-1",
        topic_id=None,
        workpackage_id=None,
        retention_class="audit",
        payload_kind="artifact",
    )
    payload = request["payload"]
    assert isinstance(payload, dict)

    with pytest.raises(HiveBusContractError, match="BUS_E_EVENT_TOO_LARGE"):
        _build_event(request | {"payload": payload | {"size_bytes": 2**63}})


@pytest.mark.parametrize(
    ("kind", "ref", "expected_code"),
    (
        ("inline", "sk-proj-lowercase-secret", "BUS_E_SECRET_CLASSIFICATION"),
        (
            "blob",
            "api-key=AIzaSyLowercaseRepresentative",
            "BUS_E_SECRET_CLASSIFICATION",
        ),
        ("artifact", "bearer-lowercase-secret", "BUS_E_SCHEMA"),
        ("inline", "authorization-lowercase-secret", "BUS_E_SECRET_CLASSIFICATION"),
        ("blob", "token-lowercase-secret", "BUS_E_SECRET_CLASSIFICATION"),
        ("artifact", "https://example.invalid/private", "BUS_E_SCHEMA"),
        ("inline", "/home/teladi/private.txt", "BUS_E_SCHEMA"),
        ("blob", "../relative-private.txt", "BUS_E_SCHEMA"),
        ("artifact", "~/.config/private.txt", "BUS_E_SCHEMA"),
        ("artifact", "prompt-text", "BUS_E_SCHEMA"),
        ("inline", "terminal-output", "BUS_E_SCHEMA"),
        ("blob", "payload-1", "BUS_E_SCHEMA"),
        ("inline", "inline:" + _digest("d"), "BUS_E_SCHEMA"),
        ("blob", "blob:" + _digest("d"), "BUS_E_SCHEMA"),
        ("artifact", "artifact:artifact-1@" + _digest("d"), "BUS_E_SCHEMA"),
    ),
)
def test_payload_reference_grammar_rejects_secrets_paths_uris_and_opaque_values(
    kind: str, ref: str, expected_code: str
) -> None:
    payload = _publish_request()["payload"]
    assert isinstance(payload, dict)
    with pytest.raises(HiveBusContractError, match=expected_code):
        _build_event(
            _publish_request()
            | {
                "event_type": "result.proposed",
                "payload": payload | {"kind": kind, "ref": ref},
            }
        )


@pytest.mark.parametrize(
    ("kind", "ref"),
    (
        ("inline", "inline:secret-not-a-digest"),
        ("blob", "blob:credential-not-a-digest"),
        ("inline", "inline:token-not-a-digest"),
        ("blob", "blob:key=not-a-digest"),
        ("inline", "inline:key-not-a-digest"),
    ),
)
def test_inline_and_blob_secret_shaped_refs_precede_general_reference_grammar(
    kind: str, ref: str
) -> None:
    """Secret-shaped malformed refs must not be downgraded to schema errors."""

    payload = _publish_request()["payload"]
    assert isinstance(payload, dict)

    with pytest.raises(HiveBusContractError, match="BUS_E_SECRET_CLASSIFICATION"):
        _build_event(
            _publish_request()
            | {
                "event_type": "result.proposed",
                "payload": payload | {"kind": kind, "ref": ref},
            }
        )


@pytest.mark.parametrize(
    ("kind", "ref"),
    (
        ("inline", "inline:not-a-digest"),
        ("blob", "blob:not-a-digest"),
    ),
)
def test_ordinary_malformed_inline_and_blob_refs_remain_schema_errors(
    kind: str, ref: str
) -> None:
    payload = _publish_request()["payload"]
    assert isinstance(payload, dict)

    with pytest.raises(HiveBusContractError, match="BUS_E_SCHEMA"):
        _build_event(
            _publish_request()
            | {
                "event_type": "result.proposed",
                "payload": payload | {"kind": kind, "ref": ref},
            }
        )


@pytest.mark.parametrize(
    ("kind", "ref"),
    (
        ("inline", "inline:" + _digest("c")),
        ("blob", "blob:" + _digest("c")),
        ("artifact", "artifact:artifact-1@" + _digest("c")),
    ),
)
def test_payload_reference_grammar_accepts_only_safe_kind_specific_references(
    kind: str, ref: str
) -> None:
    payload = _publish_request()["payload"]
    assert isinstance(payload, dict)
    event = _build_event(
        _publish_request()
        | {
            "event_type": "result.proposed",
            "payload": payload | {"kind": kind, "ref": ref},
        }
    )

    assert event.payload.kind == kind
    assert event.payload.ref == ref


def test_event_redacts_secret_classification_and_unsafe_scopes() -> None:

    with pytest.raises(HiveBusContractError, match="BUS_E_SECRET_CLASSIFICATION"):
        _build_event(_publish_request() | {"classification": "secret"})

    with pytest.raises(HiveBusContractError, match="BUS_E_TOPIC_INVALID"):
        _build_event(_publish_request() | {"partition": "repo/repo-1/topic/../task-1"})

    with pytest.raises(HiveBusContractError, match="BUS_E_REPO_SCOPE"):
        _build_event(_publish_request() | {"repo_id": "repo-2"})


@pytest.mark.parametrize(
    ("global_header_prefix", "family"),
    (
        ("policy/policy-1", "policy"),
        ("provider/provider-1/status", "provider_status"),
        ("fleet/control", "fleet_control"),
        ("fleet/resource/cpu", "fleet_resource"),
    ),
)
def test_repository_subscription_accepts_structural_global_headers_without_scope_expansion(
    global_header_prefix: str, family: str
) -> None:
    """A missing S0 global-family branch wrongly rejected this valid manifest."""

    subscription = BusSubscriptionSetV1(
        principal_id=PRODUCER_PRINCIPAL_ID,
        repo_id="repo-1",
        topic_prefixes=(
            global_header_prefix,
            "repo/repo-1",
            "repo/repo-1/task/task-1",
        ),
        event_types=("assignment.created", "result.proposed"),
    )

    assert subscription.repo_id == "repo-1"
    assert subscription.topic_prefixes == (
        global_header_prefix,
        "repo/repo-1",
        "repo/repo-1/task/task-1",
    )
    assert partition_kind(subscription.topic_prefixes[0]) == family
    assert not hasattr(subscription, "authority")


@pytest.mark.parametrize(
    "foreign_prefix",
    (
        "repo/repo-2",
        "repo/repo-2/task/task-1",
        "coordination/repo/repo-2/to/repo-3",
    ),
)
def test_global_subscription_headers_do_not_admit_foreign_repository_scope(
    foreign_prefix: str,
) -> None:
    with pytest.raises(HiveBusContractError, match="BUS_E_REPO_SCOPE"):
        BusSubscriptionSetV1(
            principal_id=PRODUCER_PRINCIPAL_ID,
            repo_id="repo-1",
            topic_prefixes=tuple(sorted(("policy/policy-1", foreign_prefix))),
            event_types=("assignment.created",),
        )


def test_subscription_set_is_an_immutable_canonical_value_without_wildcards() -> None:
    subscription = BusSubscriptionSetV1(
        principal_id=PRODUCER_PRINCIPAL_ID,
        repo_id="repo-1",
        topic_prefixes=("repo/repo-1/task/task-1", "repo/repo-1/topic/topic-1"),
        event_types=("assignment.created", "result.proposed"),
    )
    assert (
        subscription.generation
        == "sha256:fb2bacce603c4ed6fe8c95ec8462856987032035f6a60e05e57bd2fa7851d14b"
    )
    assert serialize_bus_subscription_set_v1(subscription) == {
        "schema_version": 1,
        "principal_id": PRODUCER_PRINCIPAL_ID,
        "repo_id": "repo-1",
        "topic_prefixes": ["repo/repo-1/task/task-1", "repo/repo-1/topic/topic-1"],
        "event_types": ["assignment.created", "result.proposed"],
        "generation": subscription.generation,
    }
    with pytest.raises(FrozenInstanceError):
        subscription.generation = _digest("e")  # type: ignore[misc]

    for prefixes, event_types in (
        (("repo/repo-1/*",), ("assignment.created",)),
        (("repo/repo-1/task/task-1",), ("chat.message",)),
        (("repo/repo-2/task/task-1",), ("assignment.created",)),
        (
            ("repo/repo-1/topic/topic-1", "repo/repo-1/task/task-1"),
            ("assignment.created",),
        ),
        (("repo/repo-1/task/task-1",), ("result.proposed", "assignment.created")),
    ):
        with pytest.raises(HiveBusContractError):
            BusSubscriptionSetV1(
                principal_id=PRODUCER_PRINCIPAL_ID,
                repo_id="repo-1",
                topic_prefixes=prefixes,
                event_types=event_types,
            )


@pytest.mark.parametrize(
    ("prefix", "accepted"),
    (
        ("coordination/repo/repo-1/to/repo-2", False),
        ("coordination/repo/repo-2/to/repo-1", True),
        ("coordination/repo/repo-2/to/repo-3", False),
    ),
)
def test_repository_subscription_coordination_prefixes_are_target_only(
    prefix: str, accepted: bool
) -> None:
    values = {
        "principal_id": PRODUCER_PRINCIPAL_ID,
        "repo_id": "repo-1",
        "topic_prefixes": (prefix,),
        "event_types": ("handoff.available",),
    }

    if accepted:
        subscription = BusSubscriptionSetV1(**values)
        assert subscription.topic_prefixes == (prefix,)
    else:
        with pytest.raises(HiveBusContractError, match="BUS_E_REPO_SCOPE"):
            BusSubscriptionSetV1(**values)


def test_legacy_codex_master_bus_types_import_is_absent() -> None:
    """BUS-S0 may only resolve from the renamed the_hive identity."""

    with pytest.raises(ModuleNotFoundError):
        import_module("codex_master.hive.bus_types")


def test_bus_source_has_no_legacy_test_index_reference() -> None:
    """The pure contract must not revive the removed Hive test-index sidecar."""

    source = (
        Path(__file__).resolve().parents[1]
        / "src"
        / "the_hive"
        / "hive"
        / "bus_types.py"
    ).read_text(encoding="utf-8")
    assert ".hive/test-index.v1.json" not in source
