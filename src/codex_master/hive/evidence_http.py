"""Private HTTPS adapter for the shared Hive test-evidence service."""

from __future__ import annotations

from collections.abc import Mapping, Set
import time

from codex_master.hive.evidence_service import HiveTestEvidenceService


_ROUTES = {
    ("GET", "/admin/v1/test-index/status"): "tests.read",
    ("POST", "/admin/v1/test-plan"): "tests.plan",
    ("POST", "/admin/v1/test-run"): "tests.run",
    ("GET", "/admin/v1/test-status"): "tests.read",
    ("POST", "/admin/v1/test-invalidate"): "tests.invalidate",
}


class HiveTestHttpAdapter:
    """Translate authenticated admin routes without duplicating semantics."""

    def __init__(
        self,
        service: HiveTestEvidenceService,
        *,
        execution_host_local: bool = False,
    ) -> None:
        self._service = service
        self._execution_host_local = execution_host_local

    def handle(
        self,
        method: str,
        path: str,
        payload: Mapping[str, object] | None,
        *,
        scopes: Set[str],
    ) -> Mapping[str, object]:
        route = (method, path)
        required_scope = _ROUTES.get(route)
        if required_scope is None:
            raise ValueError("test.index_invalid")
        if not isinstance(scopes, (set, frozenset)) or required_scope not in scopes:
            raise PermissionError("authority.scope_denied")
        if method == "GET":
            if payload not in (None, {}):
                raise ValueError("test.index_invalid")
            if path.endswith("test-index/status"):
                return self._service.index_status()
            request = self._service.request()
            return self._service.status(request, now_monotonic_ns=time.monotonic_ns())
        body = self._body(payload)
        if path.endswith("test-plan"):
            self._closed(body, {"changed_paths", "function_ids", "phase", "base_revision", "target_revision"})
            request = self._service.request(
                changed_paths=self._paths(body.get("changed_paths", ())),
                function_ids=self._texts(body.get("function_ids", ())),
                requested_phase=self._optional_text(body, "phase", "change"),
                base_revision=self._optional_text(body, "base_revision", "working-tree"),
                target_revision=self._optional_text(body, "target_revision", "working-tree"),
            )
            return self._service.plan(request, now_monotonic_ns=time.monotonic_ns()).public()
        if path.endswith("test-run"):
            self._closed(body, {"test_id", "index_digest"}, required={"test_id", "index_digest"})
            if not self._execution_host_local:
                return {
                    "accepted": False,
                    "reason_code": "test.run_blocked",
                    "execution_host_transport": "not_configured",
                }
            receipt = self._service.run(
                self._required_text(body, "test_id"),
                expected_index_digest=self._required_text(body, "index_digest"),
            )
            return {"evidence_id": receipt.evidence_id, "receipt": receipt.public()}
        self._closed(body, {"evidence_id", "index_digest"}, required={"evidence_id", "index_digest"})
        evidence_id = self._required_text(body, "evidence_id")
        self._service.invalidate(
            evidence_id,
            expected_index_digest=self._required_text(body, "index_digest"),
        )
        return {"invalidated": True, "evidence_id": evidence_id}

    @staticmethod
    def _body(value: object) -> Mapping[str, object]:
        if not isinstance(value, Mapping):
            raise ValueError("test.index_invalid")
        return value

    @staticmethod
    def _closed(
        value: Mapping[str, object],
        allowed: set[str],
        *,
        required: set[str] = set(),
    ) -> None:
        if not set(value) <= allowed or not required <= set(value):
            raise ValueError("test.index_invalid")

    @staticmethod
    def _required_text(value: Mapping[str, object], field: str) -> str:
        item = value.get(field)
        if not isinstance(item, str) or not item or len(item) > 2048:
            raise ValueError("test.index_invalid")
        return item

    @classmethod
    def _optional_text(
        cls, value: Mapping[str, object], field: str, default: str
    ) -> str:
        return default if field not in value else cls._required_text(value, field)

    @staticmethod
    def _texts(value: object) -> tuple[str, ...]:
        if not isinstance(value, (list, tuple)) or len(value) > 1000:
            raise ValueError("test.index_invalid")
        items = tuple(value)
        if any(not isinstance(item, str) or not item or len(item) > 2048 for item in items):
            raise ValueError("test.index_invalid")
        return items

    @classmethod
    def _paths(cls, value: object) -> tuple[str, ...]:
        items = cls._texts(value)
        if any(item.startswith("/") or ".." in item.split("/") for item in items):
            raise ValueError("test.index_invalid")
        return items


__all__ = ["HiveTestHttpAdapter"]
