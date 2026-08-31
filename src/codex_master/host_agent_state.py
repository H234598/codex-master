"""Durable, bounded replay journal for one outbound host agent."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import threading
import time
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


MAX_HOST_AGENT_ACCEPTED = 1024
MAX_HOST_AGENT_RECEIPTS = 1024
MAX_HOST_AGENT_STATE_BYTES = 4 * 1024 * 1024
_DOCUMENT = PurePosixPath("host-agent.json")
_MAX_INT = 2**63 - 1
_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z", re.ASCII)
_CLAIM_TOKEN = re.compile(r"[0-9a-f]{32}\Z", re.ASCII)
_BOOT_ID = re.compile(r"[0-9a-f-]{36}\Z", re.ASCII)


class HostAgentStateError(ValueError):
    """Stable failure raised before a host-side effect."""


def _fail(code: str) -> None:
    raise HostAgentStateError(code)


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def _digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result


def _reject_constant(_value: str) -> None:
    raise ValueError


def _lease_fence(lease: AgentLeaseV1) -> tuple[object, ...]:
    return (
        lease.operation_id,
        lease.lease_id,
        lease.attempt,
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


def _bounded_integer(value: object) -> bool:
    return type(value) is int and 0 <= value <= _MAX_INT


def _process_start_ticks(pid: int) -> int | None:
    try:
        raw = Path(f"/proc/{pid}/stat").read_bytes()
        if not raw or len(raw) > 4096:
            return None
        suffix = raw[raw.rfind(b")") + 2 :].split()
        if len(suffix) <= 19:
            return None
        value = int(suffix[19])
        return value if value >= 1 else None
    except (OSError, ValueError):
        return None


def _boot_id() -> str:
    try:
        value = Path("/proc/sys/kernel/random/boot_id").read_text("ascii").strip()
    except OSError:
        _fail("host.state_unavailable")
    if _BOOT_ID.fullmatch(value) is None:
        _fail("host.state_unavailable")
    return value


class HostAgentState:
    """Atomic accepted/claim/receipt state backed by :class:`HiveStateStore`."""

    def __init__(
        self,
        state_root: Path,
        *,
        host_ref: str,
        max_accepted: int = MAX_HOST_AGENT_ACCEPTED,
        max_receipts: int = MAX_HOST_AGENT_RECEIPTS,
    ) -> None:
        if (
            not isinstance(state_root, Path)
            or not state_root.is_absolute()
            or type(host_ref) is not str
            or _TOKEN.fullmatch(host_ref) is None
            or type(max_accepted) is not int
            or not 1 <= max_accepted <= MAX_HOST_AGENT_ACCEPTED
            or type(max_receipts) is not int
            or not 1 <= max_receipts <= MAX_HOST_AGENT_RECEIPTS
        ):
            _fail("host.state_unavailable")
        self._host_ref = host_ref
        self._max_accepted = max_accepted
        self._max_receipts = max_receipts
        self._boot_id = _boot_id()
        self._process_start_ticks = _process_start_ticks(os.getpid())
        if self._process_start_ticks is None:
            _fail("host.state_unavailable")
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
        max_accepted: int = MAX_HOST_AGENT_ACCEPTED,
        max_receipts: int = MAX_HOST_AGENT_RECEIPTS,
    ) -> HostAgentState:
        """Construct an isolated production-format store for tests."""
        return cls(
            state_root,
            host_ref=host_ref,
            max_accepted=max_accepted,
            max_receipts=max_receipts,
        )

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
            changed = self._reclaim_expired_locked(document)
            self._prune(document, lease.registry_generation)
            if len(document["receipts"]) >= self._max_receipts:
                _fail("host.receipt_limit")
            if len(document["accepted"]) >= self._max_accepted:
                if changed:
                    self._write_locked(document)
                _fail("host.accepted_limit")
            document["highest_lease_epoch"] = max(
                document["highest_lease_epoch"], lease.lease_epoch
            )
            document["highest_registry_generation"] = max(
                document["highest_registry_generation"], lease.registry_generation
            )
            document["accepted"][lease.operation_id] = {
                "fence": list(_lease_fence(lease)),
                "lease": serialize_agent_lease(lease),
                "effect_claim": None,
            }
            self._write_locked(document)
        return None

    def begin_effect(self, lease: AgentLeaseV1) -> str | None:
        """Atomically claim one mutating effect; only its winner gets a token."""
        self._check_lease(lease)
        with self._state.locked():
            document = self._read_locked()
            self._check_epoch(document, lease)
            self._check_generation(document, lease)
            record = document["accepted"].get(lease.operation_id)
            if record is None:
                _fail("host.operation_not_accepted")
            self._check_record(record, lease)
            if record["effect_claim"] is not None:
                return None
            token = secrets.token_hex(16)
            record["effect_claim"] = {
                "boot_id": self._boot_id,
                "pid": os.getpid(),
                "process_start_ticks": self._process_start_ticks,
                "thread_id": threading.get_native_id(),
                "token": token,
            }
            self._write_locked(document)
            return token

    def recover(self, lease: AgentLeaseV1) -> AgentReceiptV1 | None:
        """Recover completion, safe redelivery, or an abandoned effect."""
        saved = self.accept(lease)
        if saved is not None:
            return saved
        while True:
            with self._state.locked():
                document = self._read_locked()
                saved = document["receipts"].get(lease.operation_id)
                if saved is not None:
                    self._check_record(saved, lease)
                    return parse_agent_receipt(saved["receipt"])
                record = document["accepted"].get(lease.operation_id)
                if record is None:
                    _fail("host.operation_not_accepted")
                self._check_record(record, lease)
                claim = record["effect_claim"]
                if claim is None:
                    return None
                if not self._claim_alive(claim):
                    return self._finish_locked(
                        document,
                        lease,
                        state="unknown",
                        reason_codes=("host.operation_unknown",),
                        result=AgentResultV1(
                            lease.kind,
                            lease.action,
                            {"status": "effect_unknown"},
                        ),
                        claim_token=None,
                        allow_abandoned=True,
                    )
            time.sleep(0.01)

    def finish(
        self,
        lease: AgentLeaseV1,
        *,
        state: Literal["succeeded", "failed", "unknown"],
        reason_codes: tuple[str, ...],
        result: AgentResultV1,
        claim_token: str | None = None,
    ) -> AgentReceiptV1:
        """Atomically replace accepted work with its terminal receipt."""
        self._check_lease(lease)
        with self._state.locked():
            document = self._read_locked()
            return self._finish_locked(
                document,
                lease,
                state=state,
                reason_codes=reason_codes,
                result=result,
                claim_token=claim_token,
                allow_abandoned=False,
            )

    def receipt_count(self) -> int:
        """Return the validated terminal journal size."""
        with self._state.locked():
            return len(self._read_locked()["receipts"])

    def _finish_locked(
        self,
        document: dict[str, Any],
        lease: AgentLeaseV1,
        *,
        state: Literal["succeeded", "failed", "unknown"],
        reason_codes: tuple[str, ...],
        result: AgentResultV1,
        claim_token: str | None,
        allow_abandoned: bool,
    ) -> AgentReceiptV1:
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
        claim = accepted["effect_claim"]
        if claim is not None:
            if allow_abandoned:
                if self._claim_alive(claim):
                    _fail("host.effect_claim_active")
            elif (
                type(claim_token) is not str
                or claim.get("token") != claim_token
            ):
                _fail("host.effect_claim_mismatch")
        elif claim_token is not None:
            _fail("host.effect_claim_mismatch")
        del document["accepted"][lease.operation_id]
        document["receipts"][lease.operation_id] = {
            "fence": list(_lease_fence(lease)),
            "generation": lease.registry_generation,
            "receipt": _receipt_wire(receipt),
        }
        self._write_locked(document)
        return receipt

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
        if lease.registry_generation < document["highest_registry_generation"]:
            _fail("host.registry_generation_stale")

    @staticmethod
    def _check_record(record: Mapping[str, Any], lease: AgentLeaseV1) -> None:
        if tuple(record.get("fence", ())) != _lease_fence(lease):
            _fail("host.replay_conflict")

    def _reclaim_expired_locked(self, document: dict[str, Any]) -> bool:
        changed = False
        now = datetime.now(UTC)
        for operation_id in sorted(tuple(document["accepted"])):
            record = document["accepted"][operation_id]
            lease = self._parse_lease(record["lease"])
            if lease.deadline > now:
                continue
            claim = record["effect_claim"]
            if claim is None:
                del document["accepted"][operation_id]
                changed = True
                continue
            if self._claim_alive(claim):
                continue
            self._prune(document, lease.registry_generation)
            if len(document["receipts"]) >= self._max_receipts:
                _fail("host.receipt_limit")
            self._finish_locked(
                document,
                lease,
                state="unknown",
                reason_codes=("host.operation_unknown",),
                result=AgentResultV1(
                    lease.kind, lease.action, {"status": "effect_unknown"}
                ),
                claim_token=None,
                allow_abandoned=True,
            )
            changed = True
        return changed

    def _claim_alive(self, value: Mapping[str, Any]) -> bool:
        pid = value["pid"]
        if value["boot_id"] != self._boot_id:
            return False
        if _process_start_ticks(pid) != value["process_start_ticks"]:
            return False
        return Path(f"/proc/{pid}/task/{value['thread_id']}").is_dir()

    def _prune(self, document: dict[str, Any], generation: int) -> None:
        receipts = document["receipts"]
        required = len(receipts) - self._max_receipts + 1
        if required <= 0:
            return
        candidates = sorted(
            key
            for key, value in receipts.items()
            if value["generation"] < generation
        )
        for key in candidates[:required]:
            del receipts[key]

    def _read_locked(self) -> dict[str, Any]:
        try:
            raw = self._state.read_private_bytes(
                _DOCUMENT, max_bytes=MAX_HOST_AGENT_STATE_BYTES
            )
        except HiveStateError as error:
            if str(error) == "state_not_found":
                return {
                    "schema_version": 2,
                    "highest_lease_epoch": 0,
                    "highest_registry_generation": 0,
                    "accepted": {},
                    "receipts": {},
                }
            raise
        try:
            value = json.loads(
                raw.decode("utf-8"),
                object_pairs_hook=_strict_object,
                parse_constant=_reject_constant,
            )
        except (UnicodeError, ValueError, TypeError, RecursionError):
            _fail("host.state_unavailable")
        if (
            type(value) is not dict
            or set(value)
            != {
                "schema_version",
                "highest_lease_epoch",
                "highest_registry_generation",
                "accepted",
                "receipts",
            }
            or value["schema_version"] != 2
            or not _bounded_integer(value["highest_lease_epoch"])
            or not _bounded_integer(value["highest_registry_generation"])
            or type(value["accepted"]) is not dict
            or type(value["receipts"]) is not dict
            or len(value["accepted"]) > self._max_accepted
            or len(value["receipts"]) > self._max_receipts
        ):
            _fail("host.state_unavailable")
        highest_epoch = 0
        highest_generation = 0
        for operation_id, record in value["accepted"].items():
            if (
                type(operation_id) is not str
                or _TOKEN.fullmatch(operation_id) is None
                or type(record) is not dict
                or set(record) != {"fence", "lease", "effect_claim"}
            ):
                _fail("host.state_unavailable")
            lease = self._parse_lease(record["lease"])
            if (
                operation_id != lease.operation_id
                or lease.host_ref != self._host_ref
                or tuple(record["fence"]) != _lease_fence(lease)
            ):
                _fail("host.state_unavailable")
            self._validate_claim(record["effect_claim"])
            highest_epoch = max(highest_epoch, lease.lease_epoch)
            highest_generation = max(highest_generation, lease.registry_generation)
        for operation_id, record in value["receipts"].items():
            if (
                type(operation_id) is not str
                or _TOKEN.fullmatch(operation_id) is None
                or type(record) is not dict
                or set(record) != {"fence", "generation", "receipt"}
                or not _bounded_integer(record["generation"])
                or type(record["fence"]) is not list
                or len(record["fence"]) != 10
            ):
                _fail("host.state_unavailable")
            try:
                receipt = parse_agent_receipt(record["receipt"])
            except ValueError:
                _fail("host.state_unavailable")
            fence = tuple(record["fence"])
            if (
                operation_id != receipt.operation_id
                or fence[0] != receipt.operation_id
                or fence[1] != receipt.lease_id
                or fence[2] != receipt.attempt
                or fence[3] != self._host_ref
                or fence[4] != receipt.result.kind
                or fence[5] != receipt.result.action
                or fence[6] != record["generation"]
                or fence[7] != receipt.lease_epoch
                or fence[8] != receipt.plan_digest
                or fence[9] != receipt.arguments_digest
            ):
                _fail("host.state_unavailable")
            highest_epoch = max(highest_epoch, receipt.lease_epoch)
            highest_generation = max(highest_generation, record["generation"])
        if (
            value["highest_lease_epoch"] < highest_epoch
            or value["highest_registry_generation"] < highest_generation
        ):
            _fail("host.state_unavailable")
        return cast(dict[str, Any], value)

    @staticmethod
    def _validate_claim(value: object) -> None:
        if value is None:
            return
        if (
            type(value) is not dict
            or set(value)
            != {
                "boot_id",
                "pid",
                "process_start_ticks",
                "thread_id",
                "token",
            }
            or type(value["boot_id"]) is not str
            or _BOOT_ID.fullmatch(value["boot_id"]) is None
            or not _bounded_integer(value["pid"])
            or value["pid"] < 1
            or not _bounded_integer(value["process_start_ticks"])
            or value["process_start_ticks"] < 1
            or not _bounded_integer(value["thread_id"])
            or value["thread_id"] < 1
            or type(value["token"]) is not str
            or _CLAIM_TOKEN.fullmatch(value["token"]) is None
        ):
            _fail("host.state_unavailable")

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


__all__ = [
    "MAX_HOST_AGENT_ACCEPTED",
    "MAX_HOST_AGENT_RECEIPTS",
    "HostAgentState",
    "HostAgentStateError",
]
