from __future__ import annotations

from dataclasses import FrozenInstanceError
from datetime import UTC, datetime

import pytest

from codex_master.agent_contracts import (
    AgentContractError,
    AgentLeaseV1,
    AgentNoWorkV1,
    AgentPollV1,
    AgentReceiptV1,
    AgentResultV1,
    parse_agent_poll,
    parse_agent_receipt,
    serialize_agent_lease,
    serialize_agent_result,
)


DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64
DEADLINE = datetime(2026, 8, 30, 12, 0, 0, tzinfo=UTC)


def valid_result_payload() -> dict[str, object]:
    return {
        "ready": True,
        "reason_codes": ["resource_ready"],
        "observed_at": "2026-08-30T12:00:00Z",
        "metrics": {"cpu_percent": 12, "memory_bytes": 4096},
    }


def valid_lease(**changes: object) -> AgentLeaseV1:
    values: dict[str, object] = {
        "operation_id": "operation-one",
        "lease_id": "lease-one",
        "host_ref": "worker-one",
        "kind": "host.probe",
        "action": "collect",
        "registry_generation": 7,
        "lease_epoch": 3,
        "attempt": 1,
        "plan_digest": DIGEST_A,
        "arguments_digest": "sha256:236ae0479071b6d163a9c0e80a4d7f10714455017d65a1d59302e56f49b85f29",
        "deadline": DEADLINE,
        "arguments": {"probe_profile": "quiescence", "include_metrics": True},
    }
    values.update(changes)
    return AgentLeaseV1(**values)  # type: ignore[arg-type]


def valid_receipt_wire(**changes: object) -> dict[str, object]:
    result = {
        "kind": "host.probe",
        "action": "collect",
        "payload": valid_result_payload(),
    }
    values: dict[str, object] = {
        "schema_version": 1,
        "operation_id": "operation-one",
        "lease_id": "lease-one",
        "lease_epoch": 3,
        "attempt": 1,
        "plan_digest": DIGEST_A,
        "arguments_digest": DIGEST_B,
        "state": "succeeded",
        "reason_codes": ["resource_ready"],
        "result_digest": "sha256:83191e82ae4b39f376a9fca7a4c3ae76507d7ec8efc8824d25debf6a74aff7c8",
        "result": result,
    }
    values.update(changes)
    return values


def test_public_contract_types_are_frozen_and_constructible() -> None:
    poll = AgentPollV1(7, 3, DIGEST_A, 20)
    lease = valid_lease()
    result = AgentResultV1("host.probe", "collect", valid_result_payload())
    receipt = AgentReceiptV1(
        "operation-one",
        "lease-one",
        3,
        1,
        DIGEST_A,
        DIGEST_B,
        "succeeded",
        ("resource_ready",),
        "sha256:83191e82ae4b39f376a9fca7a4c3ae76507d7ec8efc8824d25debf6a74aff7c8",
        result,
    )
    no_work = AgentNoWorkV1(7, 3, 20)

    assert poll.max_wait_seconds == 20
    assert lease.host_ref == "worker-one"
    assert receipt.result.kind == "host.probe"
    assert no_work.max_wait_seconds == 20
    with pytest.raises(FrozenInstanceError):
        poll.max_wait_seconds = 10  # type: ignore[misc]


def test_poll_rejects_host_ref_and_unknown_fields() -> None:
    valid = {
        "schema_version": 1,
        "registry_generation": 7,
        "lease_epoch": 3,
        "capabilities_digest": DIGEST_A,
        "max_wait_seconds": 20,
    }

    assert parse_agent_poll(valid).max_wait_seconds == 20

    with pytest.raises(AgentContractError, match="agent.request_invalid"):
        parse_agent_poll(valid | {"host_ref": "worker-one"})

    with pytest.raises(AgentContractError, match="agent.request_invalid"):
        parse_agent_poll(valid | {"extra": "x"})


@pytest.mark.parametrize(
    "field,value",
    (
        ("schema_version", True),
        ("registry_generation", True),
        ("lease_epoch", False),
        ("max_wait_seconds", True),
    ),
)
def test_poll_rejects_boolean_int_fields(field: str, value: object) -> None:
    wire = {
        "schema_version": 1,
        "registry_generation": 7,
        "lease_epoch": 3,
        "capabilities_digest": DIGEST_A,
        "max_wait_seconds": 20,
    }
    wire[field] = value

    with pytest.raises(AgentContractError, match="agent.request_invalid"):
        parse_agent_poll(wire)


@pytest.mark.parametrize("seconds", (-1, 31))
def test_poll_rejects_max_wait_seconds_outside_bounded_range(seconds: int) -> None:
    with pytest.raises(AgentContractError, match="agent.request_invalid"):
        parse_agent_poll(
            {
                "schema_version": 1,
                "registry_generation": 7,
                "lease_epoch": 3,
                "capabilities_digest": DIGEST_A,
                "max_wait_seconds": seconds,
            }
        )


@pytest.mark.parametrize(
    ("kind", "action"),
    (
        ("host.probe", "plan"),
        ("ollama.instance", "collect"),
        ("unknown.kind", "collect"),
        ("host.probe", "unknown"),
    ),
)
def test_lease_serializer_enforces_exact_kind_action_allowlist(
    kind: str, action: str
) -> None:
    with pytest.raises(AgentContractError, match="agent.request_invalid"):
        serialize_agent_lease(valid_lease(kind=kind, action=action))


def test_lease_serializer_emits_exact_wire_fields_and_utc_deadline() -> None:
    payload = serialize_agent_lease(
        valid_lease(
            kind="ollama.instance",
            action="apply",
            arguments={
                "instance_ref": "ollama-main",
                "plan_id": "plan-one",
                "target_generation": 7,
            },
            arguments_digest="sha256:1368982cdefe13e87715cf30d02c602ae9fa4407f41237c42a18847df8ceb1dd",
        )
    )

    assert payload == {
        "schema_version": 1,
        "operation_id": "operation-one",
        "lease_id": "lease-one",
        "host_ref": "worker-one",
        "kind": "ollama.instance",
        "action": "apply",
        "registry_generation": 7,
        "lease_epoch": 3,
        "attempt": 1,
        "plan_digest": DIGEST_A,
        "arguments_digest": "sha256:1368982cdefe13e87715cf30d02c602ae9fa4407f41237c42a18847df8ceb1dd",
        "deadline": "2026-08-30T12:00:00Z",
        "arguments": {
            "instance_ref": "ollama-main",
            "plan_id": "plan-one",
            "target_generation": 7,
        },
    }


@pytest.mark.parametrize("field", ("command", "argv", "path", "token"))
def test_lease_serializer_rejects_forbidden_argument_keys(field: str) -> None:
    with pytest.raises(AgentContractError, match="agent.request_invalid"):
        serialize_agent_lease(
            valid_lease(
                arguments={field: "secret", "probe_profile": "quiescence"},
                arguments_digest=DIGEST_A,
            )
        )


def test_receipt_binds_all_fences_and_bounded_result() -> None:
    receipt = parse_agent_receipt(valid_receipt_wire())

    assert receipt.operation_id == "operation-one"
    assert receipt.lease_id == "lease-one"
    assert receipt.lease_epoch == 3
    assert receipt.attempt == 1
    assert receipt.plan_digest == DIGEST_A
    assert receipt.arguments_digest == DIGEST_B
    assert receipt.state == "succeeded"
    assert receipt.reason_codes == ("resource_ready",)
    assert receipt.result.kind == "host.probe"
    assert receipt.result.action == "collect"
    assert receipt.result.payload["metrics"] == {"cpu_percent": 12, "memory_bytes": 4096}


@pytest.mark.parametrize(
    "wire",
    (
        valid_receipt_wire(reason_codes=["resource_ready", "resource_ready"]),
        valid_receipt_wire(reason_codes=[f"reason_{index}" for index in range(33)]),
        valid_receipt_wire(
            result={
                "kind": "host.probe",
                "action": "collect",
                "payload": {"blob": "x" * 300000},
            },
            result_digest="sha256:b8ca31b5d490b71591f81212de2ef280dc2f3a6fd80c2e635fcb35f7a81171e6",
        ),
        valid_receipt_wire(
            result={
                "kind": "host.probe",
                "action": "collect",
                "payload": {"token": "secret"},
            },
            result_digest="sha256:0f4bfca18d84a2e8dddf8f5cfe7d6af5a20c92cb1ff5db90ee75f7a15f9a96c8",
        ),
        valid_receipt_wire(result_digest=DIGEST_A),
        valid_receipt_wire(result={"kind": "unknown.kind", "action": "collect", "payload": {}}),
        valid_receipt_wire(result={"kind": "host.probe", "action": "plan", "payload": {}}),
    ),
)
def test_receipt_parser_rejects_noncanonical_or_unbounded_values(
    wire: dict[str, object]
) -> None:
    with pytest.raises(AgentContractError, match="agent.request_invalid"):
        parse_agent_receipt(wire)


def test_receipt_parser_rejects_boolean_int_fields() -> None:
    for field in ("schema_version", "lease_epoch", "attempt"):
        wire = valid_receipt_wire()
        wire[field] = True
        with pytest.raises(AgentContractError, match="agent.request_invalid"):
            parse_agent_receipt(wire)


def test_result_serializer_emits_exact_wire_shape() -> None:
    payload = serialize_agent_result(
        AgentResultV1(
            "ollama.instance",
            "probe",
            {"instance_ref": "ollama-main", "ready": True, "reason_codes": []},
        )
    )

    assert payload == {
        "kind": "ollama.instance",
        "action": "probe",
        "payload": {
            "instance_ref": "ollama-main",
            "ready": True,
            "reason_codes": [],
        },
    }
