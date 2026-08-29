"""Allowlisted local test runner that alone mints final evidence receipts."""

from __future__ import annotations

from datetime import datetime, timezone
import importlib.metadata
import os
from pathlib import Path
import platform
import secrets
import signal
import subprocess
import sys
import time

from codex_master.hive.evidence_receipts import EvidenceReceiptV1
from codex_master.hive.indexed_tests import TestIndexV1
from codex_master.hive.evidence_planner import PlanRequestV1, evidence_context
from codex_master.hive.evidence_store import TestStatusStore


_TTL_SECONDS = {
    "deterministic": 1800,
    "integration": 600,
    "environmental": 0,
    "external": 0,
    "mandatory": 0,
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _digest_text(value: str) -> str:
    import hashlib

    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


class TestEvidenceRunner:
    """Execute one exact indexed node without shell or client-supplied result."""

    def __init__(
        self,
        repository_root: Path,
        store: TestStatusStore,
        *,
        executor_fingerprint: str,
        boot_id_digest: str,
        environment_digest: str,
    ) -> None:
        root = Path(repository_root)
        if not root.is_absolute() or not root.is_dir():
            raise ValueError("test.index_invalid")
        self._root = root.resolve()
        self._store = store
        self._executor_fingerprint = executor_fingerprint
        self._boot_id_digest = boot_id_digest
        self._environment_digest = environment_digest
        try:
            pytest_version = importlib.metadata.version("pytest")
        except importlib.metadata.PackageNotFoundError:
            pytest_version = "unavailable"
        self._runner_version_digest = _digest_text(
            f"pytest:{pytest_version};python:{platform.python_version()}"
        )

    @property
    def runner_version_digest(self) -> str:
        return self._runner_version_digest

    @property
    def executor_fingerprint(self) -> str:
        return self._executor_fingerprint

    @property
    def boot_id_digest(self) -> str:
        return self._boot_id_digest

    @property
    def environment_digest(self) -> str:
        return self._environment_digest

    def run(
        self,
        index: TestIndexV1,
        test_id: str,
        *,
        expected_index_digest: str,
    ) -> EvidenceReceiptV1:
        if index.digest != expected_index_digest:
            raise ValueError("test.generation_stale")
        tests = {item.test_id: item for item in index.tests}
        if test_id not in tests:
            raise ValueError("test.test_uncollectable")
        test = tests[test_id]
        if test.runner != "pytest":
            raise ValueError("test.run_blocked")
        target = (self._root / test.path).resolve(strict=True)
        try:
            target.relative_to(self._root)
        except ValueError:
            raise ValueError("test.index_invalid") from None
        if not target.is_file():
            raise ValueError("test.test_uncollectable")
        request = PlanRequestV1(
            repository_id=index.repository_id,
            index_digest=index.digest,
            base_revision="runner",
            target_revision="runner",
            changed_paths=(),
            function_ids=(),
            requested_phase="change",
            executor_fingerprint=self._executor_fingerprint,
            boot_id_digest=self._boot_id_digest,
            runner_version_digest=self._runner_version_digest,
            environment_digest=self._environment_digest,
        )
        context = evidence_context(request, index, test)
        attempt_id = "attempt-" + secrets.token_hex(16)
        started_at = _utc_now()
        started_ns = time.monotonic_ns()
        result, reason = self._execute(test.path, test.node_id, test.timeout_seconds)
        finished_ns = time.monotonic_ns()
        finished_at = _utc_now()
        ttl = _TTL_SECONDS[test.cooldown_class] if result == "passed" else 0
        receipt = EvidenceReceiptV1(
            repository_id=context.repository_id,
            index_digest=context.index_digest,
            function_ids=context.function_ids,
            test_id=context.test_id,
            source_digest_set_digest=context.source_digest_set_digest,
            test_digest=context.test_digest,
            assertion_digest=context.assertion_digest,
            dependency_digest_set_digest=context.dependency_digest_set_digest,
            executor_fingerprint=context.executor_fingerprint,
            boot_id_digest=context.boot_id_digest,
            runner_version_digest=context.runner_version_digest,
            environment_digest=context.environment_digest,
            attempt_id=attempt_id,
            started_at=started_at,
            finished_at=finished_at,
            started_monotonic_ns=started_ns,
            finished_monotonic_ns=finished_ns,
            result=result,
            reason_code=reason,
            duration_ms=(finished_ns - started_ns) // 1_000_000,
            cooldown_class=test.cooldown_class,
            expires_monotonic_ns=finished_ns + ttl * 1_000_000_000,
        )
        self._store.put(receipt)
        return receipt

    def _execute(self, path: str, node_id: str, timeout_seconds: int) -> tuple[str, str]:
        argv = [sys.executable, "-m", "pytest", "-q", f"{path}::{node_id}"]
        environment = {
            "PATH": os.defpath,
            "PYTHONPATH": os.pathsep.join((str(self._root / "src"), str(self._root))),
            "PYTHONDONTWRITEBYTECODE": "1",
            "LC_ALL": "C.UTF-8",
        }
        try:
            process = subprocess.Popen(
                argv,
                cwd=self._root,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
        except OSError:
            return "blocked", "test.run_blocked"
        try:
            return_code = process.wait(timeout=timeout_seconds)
        except subprocess.TimeoutExpired:
            self._terminate_own_group(process)
            return "blocked", "test.run_timeout"
        except (KeyboardInterrupt, SystemExit):
            self._terminate_own_group(process)
            raise
        if return_code == 0:
            return "passed", "test.run_passed"
        return "failed", "test.run_failed"

    @staticmethod
    def _terminate_own_group(process: subprocess.Popen[bytes]) -> None:
        if process.poll() is not None:
            return
        try:
            group = os.getpgid(process.pid)
        except ProcessLookupError:
            return
        if group != process.pid:
            process.terminate()
            process.wait(timeout=1)
            return
        os.killpg(group, signal.SIGTERM)
        try:
            process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            os.killpg(group, signal.SIGKILL)
            process.wait(timeout=1)


__all__ = ["TestEvidenceRunner"]
