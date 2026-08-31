"""Durable, bounded replay journal for one outbound host agent."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
import hashlib
import json
from pathlib import Path, PurePosixPath
from typing import Any, Literal, cast

from codex_master.agent_contracts import (
    AgentLeaseV1,
    AgentReceiptV1,
    AgentResultV1,
    parse_agent_receipt,
    serialize_agent_lease,
    serialize_agent_result,
)
from codex_master.hive.state import HiveStateError, HiveStateStore


MAX_HOST_AGENT_RECEIPTS = 1024
MAX_HOST_AGENT_STATE_BYTES = 4 * 1024 * 1024
_DOCUMENT = PurePosixPath("host-agent.json")


class HostAgentStateError(ValueError):
    """Stable failure raised before a host-side effect."""


def _fail(code: str) -> None:
    raise HostAgentStateError(code)


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode()


def _digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


def _lease_fence(lease: AgentLeaseV1) -> tuple[object, ...]:
    return (
        lease.host_ref,
        lease.kind,
        lease.action,
        lease.registry_generation,
        lease.lease_epoch,
        lease.plan_digest,
        lease.arguments_digest,
    )


def _receipt_wire(receipt: AgentReceiptV1) -> dict[str, object]:
    return {
        "schema_version": 1,
        "operation_id": receipt.operation_id,
        "lease_id": receipt.lease_id,
        "lease_epoch": receipt.lease_epoch,
        "attempt": receipt.attempt,
        "plan_digest": receipt.plan_digest,
        "arguments_digest": receipt.arguments_digest,
        "state": receipt.state,
        "reason_codes": list(receipt.reason_codes),
        "result_digest": receipt.result_digest,
        "result": serialize_agent_result(receipt.result),
    }


class HostAgentState:
    """Atomic accepted/effect/receipt state backed by :class:`HiveStateStore`."""

    def __init__(
        self,
        state_root: Path,
        *,
        host_ref: str,
        max_receipts: int = MAX_HOST_AGENT_RECEIPTS,
    ) -> None:
        if (
            not isinstance(state_root, Path)
            or not state_root.is_absolute()
            or not host_ref
        ):
            _fail("host.state_unavailable")
        if (
            type(max_receipts) is not int
            or not 1 <= max_receipts <= MAX_HOST_AGENT_RECEIPTS
        ):
            _fail("host.state_unavailable")
        self._host_ref = host_ref
        self._max_receipts = max_receipts
        try:
            self._state = HiveStateStore(state_root / "host-agent")
            with self._state.locked():
                self._write_locked(self._read_locked())
        except (HiveStateError, OSError, ValueError):
            _fail("host.state_unavailable")

    @classmethod
    def for_test(
        cls,
        state_root: Path,
        *,
        host_ref: str,
        max_receipts: int = MAX_HOST_AGENT_RECEIPTS,
    ) -> HostAgentState:
        """Construct an isolated production-format store for tests."""
        return cls(state_root, host_ref=host_ref, max_receipts=max_receipts)

    def accept(self, lease: AgentLeaseV1) -> AgentReceiptV1 | None:
        """Fence and durably accept a lease, or return its saved receipt."""
        self._check_lease(lease)
        with self._state.locked():
            document = self._read_locked()
            saved = document["receipts"].get(lease.operation_id)
            if saved is not None:
                self._check_record(saved, lease)
                return parse_agent_receipt(saved["receipt"])
            self._check_epoch(document, lease)
            self._check_generation(document, lease)
            accepted = document["accepted"].get(lease.operation_id)
            if accepted is not None:
                self._check_record(accepted, lease)
                return None
            self._prune(document, lease.registry_generation)
            if len(document["receipts"]) >= self._max_receipts:
                _fail("host.receipt_limit")
            document["highest_lease_epoch"] = max(
                document["highest_lease_epoch"], lease.lease_epoch
            )
            document["accepted"][lease.operation_id] = {
                "fence": list(_lease_fence(lease)),
                "lease": serialize_agent_lease(lease),
                "effect_started": False,
            }
            self._write_locked(document)
        return None

    def begin_effect(self, lease: AgentLeaseV1) -> None:
        """Durably mark the point after which a mutating effect cannot replay."""
        self._check_lease(lease)
        with self._state.locked():
            document = self._read_locked()
            self._check_epoch(document, lease)
            record = document["accepted"].get(lease.operation_id)
            if record is None:
                _fail("host.operation_not_accepted")
            self._check_record(record, lease)
            record["effect_started"] = True
            self._write_locked(document)

    def recover(self, lease: AgentLeaseV1) -> AgentReceiptV1 | None:
        """Recover saved completion or turn an interrupted effect into unknown."""
        saved = self.accept(lease)
        if saved is not None:
            return saved
        with self._state.locked():
            document = self._read_locked()
            saved = document["receipts"].get(lease.operation_id)
            if saved is not None:
                self._check_record(saved, lease)
                return parse_agent_receipt(saved["receipt"])
            record = document["accepted"].get(lease.operation_id)
            if record is None:
                _fail("host.operation_not_accepted")
            if not record["effect_started"]:
                return None
        unknown = AgentResultV1(lease.kind, lease.action, {"status": "effect_unknown"})
        return self.finish(
            lease,
            state="unknown",
            reason_codes=("host.operation_unknown",),
            result=unknown,
        )

    def finish(
        self,
        lease: AgentLeaseV1,
        *,
        state: Literal["succeeded", "failed", "unknown"],
        reason_codes: tuple[str, ...],
        result: AgentResultV1,
    ) -> AgentReceiptV1:
        """Atomically replace accepted work with its terminal receipt."""
        self._check_lease(lease)
        receipt = AgentReceiptV1(
            lease.operation_id,
            lease.lease_id,
            lease.lease_epoch,
            lease.attempt,
            lease.plan_digest,
            lease.arguments_digest,
            state,
            reason_codes,
            _digest(serialize_agent_result(result)),
            result,
        )
        with self._state.locked():
            document = self._read_locked()
            existing = document["receipts"].get(lease.operation_id)
            if existing is not None:
                self._check_record(existing, lease)
                saved = parse_agent_receipt(existing["receipt"])
                if saved != receipt:
                    _fail("host.replay_conflict")
                return saved
            accepted = document["accepted"].get(lease.operation_id)
            if accepted is None:
                _fail("host.operation_not_accepted")
            self._check_record(accepted, lease)
            del document["accepted"][lease.operation_id]
            document["receipts"][lease.operation_id] = {
                "fence": list(_lease_fence(lease)),
                "generation": lease.registry_generation,
                "receipt": _receipt_wire(receipt),
            }
            self._write_locked(document)
        return receipt

    def receipt_count(self) -> int:
        """Return the validated terminal journal size."""
        with self._state.locked():
            return len(self._read_locked()["receipts"])

    def _check_lease(self, lease: AgentLeaseV1) -> None:
        if type(lease) is not AgentLeaseV1:
            _fail("host.request_invalid")
        if lease.host_ref != self._host_ref:
            _fail("host.identity_mismatch")

    @staticmethod
    def _check_epoch(document: Mapping[str, Any], lease: AgentLeaseV1) -> None:
        if lease.lease_epoch < document["highest_lease_epoch"]:
            _fail("host.lease_epoch_stale")

    @staticmethod
    def _check_generation(document: Mapping[str, Any], lease: AgentLeaseV1) -> None:
        generations = [
            record["generation"] for record in document["receipts"].values()
        ]
        generations.extend(
            record["lease"]["registry_generation"]
            for record in document["accepted"].values()
        )
        if generations and lease.registry_generation < max(generations):
            _fail("host.registry_generation_stale")

    @staticmethod
    def _check_record(record: Mapping[str, Any], lease: AgentLeaseV1) -> None:
        if tuple(record.get("fence", ())) != _lease_fence(lease):
            _fail("host.replay_conflict")

    def _prune(self, document: dict[str, Any], generation: int) -> None:
        receipts = document["receipts"]
        while len(receipts) >= self._max_receipts:
            candidates = sorted(
                key
                for key, value in receipts.items()
                if value["generation"] < generation
            )
            if not candidates:
                return
            del receipts[candidates[0]]

    def _read_locked(self) -> dict[str, Any]:
        try:
            raw = self._state.read_private_bytes(
                _DOCUMENT, max_bytes=MAX_HOST_AGENT_STATE_BYTES
            )
        except HiveStateError as error:
            if str(error) == "state_not_found":
                return {
                    "schema_version": 1,
                    "highest_lease_epoch": 0,
                    "accepted": {},
                    "receipts": {},
                }
            raise
        try:
            value = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
            _fail("host.state_unavailable")
        if (
            type(value) is not dict
            or set(value)
            != {"schema_version", "highest_lease_epoch", "accepted", "receipts"}
            or value["schema_version"] != 1
        ):
            _fail("host.state_unavailable")
        if (
            type(value["highest_lease_epoch"]) is not int
            or value["highest_lease_epoch"] < 0
            or type(value["accepted"]) is not dict
            or type(value["receipts"]) is not dict
            or len(value["receipts"]) > self._max_receipts
        ):
            _fail("host.state_unavailable")
        for record in value["accepted"].values():
            if (
                type(record) is not dict
                or set(record) != {"fence", "lease", "effect_started"}
                or type(record["effect_started"]) is not bool
            ):
                _fail("host.state_unavailable")
            self._parse_lease(record["lease"])
        for record in value["receipts"].values():
            if (
                type(record) is not dict
                or set(record) != {"fence", "generation", "receipt"}
                or type(record["generation"]) is not int
            ):
                _fail("host.state_unavailable")
            parse_agent_receipt(record["receipt"])
        return cast(dict[str, Any], value)

    @staticmethod
    def _parse_lease(value: object) -> AgentLeaseV1:
        if type(value) is not dict:
            _fail("host.state_unavailable")
        doc = cast(dict[str, object], value)
        try:
            if (
                set(doc)
                != {
                    "schema_version",
                    "operation_id",
                    "lease_id",
                    "host_ref",
                    "kind",
                    "action",
                    "registry_generation",
                    "lease_epoch",
                    "attempt",
                    "plan_digest",
                    "arguments_digest",
                    "deadline",
                    "arguments",
                }
                or doc["schema_version"] != 1
            ):
                _fail("host.state_unavailable")
            deadline = datetime.strptime(
                cast(str, doc["deadline"]), "%Y-%m-%dT%H:%M:%SZ"
            ).replace(tzinfo=UTC)
            return AgentLeaseV1(
                deadline=deadline,
                **{
                    key: item
                    for key, item in doc.items()
                    if key not in {"schema_version", "deadline"}
                },
            )  # type: ignore[arg-type]
        except (TypeError, ValueError):
            _fail("host.state_unavailable")

    def _write_locked(self, document: Mapping[str, object]) -> None:
        encoded = _canonical(document) + b"\n"
        if len(encoded) > MAX_HOST_AGENT_STATE_BYTES:
            _fail("host.state_unavailable")
        self._state.replace_private_bytes(_DOCUMENT, encoded)


__all__ = ["MAX_HOST_AGENT_RECEIPTS", "HostAgentState", "HostAgentStateError"]
