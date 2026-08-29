"""Single service contract shared by Hive test-evidence adapters."""

from __future__ import annotations

from collections.abc import Sequence
import hashlib
import json
import os
from pathlib import Path
import platform
import stat

from codex_master.hive.evidence_receipts import EvidenceReceiptV1
from codex_master.hive.indexed_tests import TestIndexV1
from codex_master.hive.evidence_planner import PlanRequestV1, PlanResultV1, TestPlanner
from codex_master.hive.evidence_runner import TestEvidenceRunner
from codex_master.hive.evidence_store import TestStatusStore


_MAX_INDEX_BYTES = 50 * 1024 * 1024


def _digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def load_test_index(repository_root: Path) -> TestIndexV1:
    root = Path(repository_root).resolve()
    target = root / ".hive" / "test-index.v1.json"
    try:
        descriptor = os.open(target, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError:
        raise ValueError("test.index_missing") from None
    except OSError:
        raise ValueError("test.index_invalid") from None
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > _MAX_INDEX_BYTES:
            raise ValueError("test.index_invalid")
        raw = os.read(descriptor, _MAX_INDEX_BYTES + 1)
    finally:
        os.close(descriptor)
    if len(raw) > _MAX_INDEX_BYTES:
        raise ValueError("test.index_invalid")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError, RecursionError):
        raise ValueError("test.index_invalid") from None
    return TestIndexV1.from_mapping(value)


def build_local_test_service(
    repository_root: Path | None = None,
    state_root: Path | None = None,
) -> HiveTestEvidenceService:
    root = (repository_root or Path.cwd()).resolve()
    index = load_test_index(root)
    if state_root is None:
        base = Path(
            os.environ.get("CODEX_MASTER_MCP_STATE")
            or os.environ.get("CODEX_AGENT_MCP_STATE")
            or "~/.local/state/codex-master-mcp"
        ).expanduser()
        state_root = base / "test-evidence" / "v1"
    machine_material = bytearray(platform.machine().encode("utf-8"))
    try:
        machine_material.extend(Path("/etc/machine-id").read_bytes()[:256])
    except OSError:
        machine_material.extend(b"machine-id-unavailable")
    machine_material.extend(os.fsencode(root))
    executor = _digest(bytes(machine_material))
    try:
        boot_material = Path("/proc/sys/kernel/random/boot_id").read_bytes()[:256]
    except OSError:
        boot_material = f"process:{os.getpid()}".encode("ascii")
    boot = _digest(boot_material)
    environment = _digest(
        f"python:{platform.python_version()};system:{platform.system()};machine:{platform.machine()}".encode()
    )
    store = TestStatusStore(Path(state_root))
    runner = TestEvidenceRunner(
        root,
        store,
        executor_fingerprint=executor,
        boot_id_digest=boot,
        environment_digest=environment,
    )
    return HiveTestEvidenceService(index, store, runner)


class HiveTestEvidenceService:
    """Bind validated index, local executor and private evidence state."""

    def __init__(
        self,
        index: TestIndexV1,
        store: TestStatusStore,
        runner: TestEvidenceRunner,
    ) -> None:
        self._index = index
        self._store = store
        self._runner = runner
        self._planner = TestPlanner()

    def request(
        self,
        *,
        changed_paths: Sequence[str] = (),
        function_ids: Sequence[str] = (),
        requested_phase: str = "change",
        base_revision: str = "working-tree",
        target_revision: str = "working-tree",
    ) -> PlanRequestV1:
        return PlanRequestV1(
            repository_id=self._index.repository_id,
            index_digest=self._index.digest,
            base_revision=base_revision,
            target_revision=target_revision,
            changed_paths=tuple(sorted(set(changed_paths))),
            function_ids=tuple(sorted(set(function_ids))),
            requested_phase=requested_phase,
            executor_fingerprint=self._runner.executor_fingerprint,
            boot_id_digest=self._runner.boot_id_digest,
            runner_version_digest=self._runner.runner_version_digest,
            environment_digest=self._runner.environment_digest,
        )

    def index_status(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "repository_id": self._index.repository_id,
            "index_generation": self._index.generation,
            "index_digest": self._index.digest,
            "valid": True,
            "function_count": len(self._index.functions),
            "test_count": len(self._index.tests),
            "gate_count": len(self._index.gates),
        }

    def plan(self, request: PlanRequestV1, *, now_monotonic_ns: int) -> PlanResultV1:
        receipts = {
            test.test_id: receipt
            for test in self._index.tests
            if (
                receipt := self._store.latest(
                    self._index.repository_id,
                    self._runner.executor_fingerprint,
                    test.test_id,
                )
            )
            is not None
        }
        revoked = frozenset(
            receipt.evidence_id
            for receipt in receipts.values()
            if self._store.is_revoked(
                self._index.repository_id,
                self._runner.executor_fingerprint,
                receipt.evidence_id,
            )
        )
        return self._planner.plan(
            request,
            self._index,
            evidence=receipts,
            revoked_evidence_ids=revoked,
            now_monotonic_ns=now_monotonic_ns,
        )

    def run(self, test_id: str, *, expected_index_digest: str) -> EvidenceReceiptV1:
        return self._runner.run(
            self._index,
            test_id,
            expected_index_digest=expected_index_digest,
        )

    def status(self, request: PlanRequestV1, *, now_monotonic_ns: int) -> dict[str, object]:
        return self._store.status(self._index, request, now_monotonic_ns=now_monotonic_ns)

    def invalidate(self, evidence_id: str, *, expected_index_digest: str) -> None:
        if expected_index_digest != self._index.digest:
            raise ValueError("test.generation_stale")
        self._store.invalidate(
            self._index.repository_id,
            self._runner.executor_fingerprint,
            evidence_id,
        )


__all__ = ["HiveTestEvidenceService", "build_local_test_service", "load_test_index"]
