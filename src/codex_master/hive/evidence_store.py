"""Private bounded persistence and public status projection for test evidence."""

from __future__ import annotations

from collections import Counter
import hashlib
from pathlib import Path, PurePosixPath
import re

from codex_master.hive.state import HiveStateError, HiveStateStore
from codex_master.hive.evidence_receipts import EvidenceReceiptV1, evaluate_evidence_reuse
from codex_master.hive.indexed_tests import TestIndexV1
from codex_master.hive.evidence_planner import PlanRequestV1, evidence_context


_REPOSITORY_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}\Z")
_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_MAX_RECEIPTS = 700
_MAX_REVOKED = 700
_MAX_RUNNING = 700
_MAX_STATE_BYTES = 4 * 1024 * 1024
_STATUSES = ("unverified", "running", "passed", "failed", "stale", "blocked")


class TestStatusStore:
    """Store bounded receipt metadata using existing hardened Hive state primitives."""

    def __init__(self, root: Path) -> None:
        self._state = HiveStateStore(root)

    def put(self, receipt: EvidenceReceiptV1) -> None:
        if not isinstance(receipt, EvidenceReceiptV1):
            raise HiveStateError("invalid_state_document")
        relative = self._relative(receipt.repository_id, receipt.executor_fingerprint)
        with self._state.locked() as state:
            document = self._load_locked(state, relative, receipt.repository_id, receipt.executor_fingerprint)
            records = [
                item
                for item in document["receipts"]
                if isinstance(item, dict) and self._evidence_id(item) != receipt.evidence_id
            ]
            records.append(receipt.public())
            records.sort(
                key=lambda item: (
                    int(item.get("finished_monotonic_ns", -1)),
                    str(item.get("attempt_id", "")),
                )
            )
            document["receipts"] = records[-_MAX_RECEIPTS:]
            state.replace_json_locked(relative, document)

    def begin_attempt(
        self,
        repository_id: str,
        executor_fingerprint: str,
        test_id: str,
        attempt_id: str,
        *,
        started_monotonic_ns: int,
        expires_monotonic_ns: int,
    ) -> None:
        self._validate_attempt(test_id, attempt_id, started_monotonic_ns, expires_monotonic_ns)
        relative = self._relative(repository_id, executor_fingerprint)
        with self._state.locked() as state:
            document = self._load_locked(state, relative, repository_id, executor_fingerprint)
            running = [item for item in document["running"] if item["test_id"] != test_id]
            running.append(
                {
                    "test_id": test_id,
                    "attempt_id": attempt_id,
                    "started_monotonic_ns": started_monotonic_ns,
                    "expires_monotonic_ns": expires_monotonic_ns,
                }
            )
            document["running"] = sorted(running, key=lambda item: item["test_id"])[-_MAX_RUNNING:]
            state.replace_json_locked(relative, document)

    def cancel_attempt(
        self,
        repository_id: str,
        executor_fingerprint: str,
        test_id: str,
        attempt_id: str,
    ) -> None:
        relative = self._relative(repository_id, executor_fingerprint)
        with self._state.locked() as state:
            document = self._load_locked(state, relative, repository_id, executor_fingerprint)
            document["running"] = [
                item
                for item in document["running"]
                if not (item["test_id"] == test_id and item["attempt_id"] == attempt_id)
            ]
            state.replace_json_locked(relative, document)

    def active_attempt(
        self,
        repository_id: str,
        executor_fingerprint: str,
        test_id: str,
        *,
        now_monotonic_ns: int,
    ) -> dict[str, object] | None:
        relative = self._relative(repository_id, executor_fingerprint)
        with self._state.locked() as state:
            document = self._load_locked(state, relative, repository_id, executor_fingerprint)
        return next(
            (
                dict(item)
                for item in document["running"]
                if item["test_id"] == test_id and now_monotonic_ns < item["expires_monotonic_ns"]
            ),
            None,
        )

    def latest(
        self, repository_id: str, executor_fingerprint: str, test_id: str
    ) -> EvidenceReceiptV1 | None:
        relative = self._relative(repository_id, executor_fingerprint)
        with self._state.locked() as state:
            document = self._load_locked(state, relative, repository_id, executor_fingerprint)
        matches: list[EvidenceReceiptV1] = []
        for raw in document["receipts"]:
            try:
                receipt = EvidenceReceiptV1.from_mapping(raw)
            except (TypeError, ValueError):
                continue
            if receipt.test_id == test_id:
                matches.append(receipt)
        return max(
            matches,
            key=lambda item: (item.finished_monotonic_ns, item.attempt_id),
            default=None,
        )

    def invalidate(self, repository_id: str, executor_fingerprint: str, evidence_id: str) -> None:
        if not isinstance(evidence_id, str) or not _DIGEST_RE.fullmatch(evidence_id):
            raise HiveStateError("invalid_state_document")
        relative = self._relative(repository_id, executor_fingerprint)
        with self._state.locked() as state:
            document = self._load_locked(state, relative, repository_id, executor_fingerprint)
            revoked = sorted({*document["revoked"], evidence_id})
            document["revoked"] = revoked[-_MAX_REVOKED:]
            state.replace_json_locked(relative, document)

    def is_revoked(self, repository_id: str, executor_fingerprint: str, evidence_id: str) -> bool:
        relative = self._relative(repository_id, executor_fingerprint)
        with self._state.locked() as state:
            document = self._load_locked(state, relative, repository_id, executor_fingerprint)
        return evidence_id in document["revoked"]

    def status(
        self,
        index: TestIndexV1,
        request: PlanRequestV1,
        *,
        now_monotonic_ns: int,
    ) -> dict[str, object]:
        items: list[dict[str, object]] = []
        for test in index.tests:
            running = self.active_attempt(
                index.repository_id,
                request.executor_fingerprint,
                test.test_id,
                now_monotonic_ns=now_monotonic_ns,
            )
            if running is not None:
                items.append(
                    {
                        "test_id": test.test_id,
                        "status": "running",
                        "last_duration_ms": None,
                        "cooldown_class": test.cooldown_class,
                        "reuse_eligible": False,
                        "remaining_cooldown_seconds": 0,
                        "reason_code": "test.run_running",
                    }
                )
                continue
            receipt = self.latest(index.repository_id, request.executor_fingerprint, test.test_id)
            revoked = bool(
                receipt
                and self.is_revoked(
                    index.repository_id,
                    request.executor_fingerprint,
                    receipt.evidence_id,
                )
            )
            decision = evaluate_evidence_reuse(
                receipt,
                evidence_context(request, index, test),
                now_monotonic_ns=now_monotonic_ns,
                revoked=revoked,
            )
            status = self._status(receipt, decision.action)
            items.append(
                {
                    "test_id": test.test_id,
                    "status": status,
                    "last_duration_ms": receipt.duration_ms if receipt else None,
                    "cooldown_class": test.cooldown_class,
                    "reuse_eligible": decision.action == "reuse",
                    "remaining_cooldown_seconds": decision.remaining_cooldown_seconds,
                    "reason_code": decision.reason_code,
                }
            )
        counts = Counter(item["status"] for item in items)
        return {
            "schema_version": 1,
            "repository_id": index.repository_id,
            "index_generation": index.generation,
            "index_digest": index.digest,
            "counts": {name: counts[name] for name in _STATUSES},
            "items": items,
        }

    @staticmethod
    def _status(receipt: EvidenceReceiptV1 | None, action: str) -> str:
        if receipt is None:
            return "unverified"
        if receipt.result == "passed":
            return "passed" if action == "reuse" else "stale"
        if receipt.result == "failed":
            return "failed"
        if receipt.result == "blocked":
            return "blocked"
        return "stale"

    @staticmethod
    def _relative(repository_id: str, executor_fingerprint: str) -> PurePosixPath:
        if not isinstance(repository_id, str) or not _REPOSITORY_RE.fullmatch(repository_id):
            raise HiveStateError("invalid_state_path")
        if not isinstance(executor_fingerprint, str) or not _DIGEST_RE.fullmatch(executor_fingerprint):
            raise HiveStateError("invalid_state_path")
        executor_key = hashlib.sha256(executor_fingerprint.encode("ascii")).hexdigest()
        return PurePosixPath(repository_id, executor_key + ".json")

    @staticmethod
    def _empty(repository_id: str, executor_fingerprint: str) -> dict[str, object]:
        return {
            "schema_version": 1,
            "repository_id": repository_id,
            "executor_fingerprint": executor_fingerprint,
            "receipts": [],
            "revoked": [],
            "running": [],
        }

    @classmethod
    def _load_locked(
        cls,
        state: HiveStateStore,
        relative: PurePosixPath,
        repository_id: str,
        executor_fingerprint: str,
    ) -> dict[str, object]:
        try:
            document = dict(state.read_json_locked(relative, max_bytes=_MAX_STATE_BYTES))
        except HiveStateError as exc:
            if str(exc) == "state_not_found":
                return cls._empty(repository_id, executor_fingerprint)
            raise
        expected = {
            "schema_version",
            "repository_id",
            "executor_fingerprint",
            "receipts",
            "revoked",
            "running",
        }
        if (
            set(document) != expected
            or document["schema_version"] != 1
            or document["repository_id"] != repository_id
            or document["executor_fingerprint"] != executor_fingerprint
            or not isinstance(document["receipts"], list)
            or len(document["receipts"]) > _MAX_RECEIPTS
            or not isinstance(document["revoked"], list)
            or len(document["revoked"]) > _MAX_REVOKED
            or any(not isinstance(value, str) or not _DIGEST_RE.fullmatch(value) for value in document["revoked"])
            or not isinstance(document["running"], list)
            or len(document["running"]) > _MAX_RUNNING
            or any(not cls._valid_attempt(item) for item in document["running"])
        ):
            raise HiveStateError("invalid_state_document")
        return document

    @staticmethod
    def _evidence_id(value: dict[str, object]) -> str | None:
        try:
            return EvidenceReceiptV1.from_mapping(value).evidence_id
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _validate_attempt(
        test_id: str,
        attempt_id: str,
        started_monotonic_ns: int,
        expires_monotonic_ns: int,
    ) -> None:
        if not TestStatusStore._valid_attempt(
            {
                "test_id": test_id,
                "attempt_id": attempt_id,
                "started_monotonic_ns": started_monotonic_ns,
                "expires_monotonic_ns": expires_monotonic_ns,
            }
        ):
            raise HiveStateError("invalid_state_document")

    @staticmethod
    def _valid_attempt(value: object) -> bool:
        return bool(
            isinstance(value, dict)
            and set(value)
            == {"test_id", "attempt_id", "started_monotonic_ns", "expires_monotonic_ns"}
            and isinstance(value["test_id"], str)
            and 1 <= len(value["test_id"]) <= 2048
            and isinstance(value["attempt_id"], str)
            and 1 <= len(value["attempt_id"]) <= 128
            and isinstance(value["started_monotonic_ns"], int)
            and not isinstance(value["started_monotonic_ns"], bool)
            and isinstance(value["expires_monotonic_ns"], int)
            and not isinstance(value["expires_monotonic_ns"], bool)
            and 0 <= value["started_monotonic_ns"] < value["expires_monotonic_ns"]
            and value["expires_monotonic_ns"] - value["started_monotonic_ns"]
            <= 3600 * 1_000_000_000
        )


__all__ = ["TestStatusStore"]
