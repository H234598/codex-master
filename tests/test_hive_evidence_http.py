from __future__ import annotations

from pathlib import Path

import pytest

from codex_master.hive.evidence_http import HiveTestHttpAdapter

from test_hive_test_service import service


def test_http_read_and_plan_share_inprocess_service_contract(tmp_path: Path) -> None:
    evidence_service, _ = service(tmp_path)
    adapter = HiveTestHttpAdapter(evidence_service)

    index = adapter.handle(
        "GET", "/admin/v1/test-index/status", None, scopes={"tests.read"}
    )
    planned = adapter.handle(
        "POST",
        "/admin/v1/test-plan",
        {"changed_paths": ["src/example.py"], "phase": "change"},
        scopes={"tests.plan"},
    )

    assert index == evidence_service.index_status()
    assert planned["tests"][0]["action"] == "run"


def test_http_remote_run_fails_closed_until_execution_host_transport_exists(tmp_path: Path) -> None:
    evidence_service, test_id = service(tmp_path)
    adapter = HiveTestHttpAdapter(evidence_service)

    result = adapter.handle(
        "POST",
        "/admin/v1/test-run",
        {"test_id": test_id, "index_digest": evidence_service.index_status()["index_digest"]},
        scopes={"tests.run"},
    )

    assert result == {
        "accepted": False,
        "reason_code": "test.run_blocked",
        "execution_host_transport": "not_configured",
    }


def test_http_local_execution_requires_explicit_host_binding_and_scope(tmp_path: Path) -> None:
    evidence_service, test_id = service(tmp_path)
    adapter = HiveTestHttpAdapter(evidence_service, execution_host_local=True)
    payload = {
        "test_id": test_id,
        "index_digest": evidence_service.index_status()["index_digest"],
    }

    with pytest.raises(PermissionError, match="authority.scope_denied"):
        adapter.handle("POST", "/admin/v1/test-run", payload, scopes={"tests.read"})
    result = adapter.handle("POST", "/admin/v1/test-run", payload, scopes={"tests.run"})

    assert result["receipt"]["result"] == "passed"
