"""Closed public CLI contract for the Google inventory authority.

The defect these tests protect against is an adapter that restores a legacy
route or reflects an authority's sensitive internal values to stdout.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path
import re
import subprocess
import sys

import pytest

from the_hive import google_account_manager_cli as cli


_ROOT = Path(__file__).resolve().parents[1]
_SCRIPT = _ROOT / "scripts" / "google-account-manager"
_FIXED_NONFIXTURE_LITERALS = {
    "google-account-manager",
    "google-account-subject-id",
    "google.oauth-client-import",
}
_CANDIDATE_TEST_FILES = (
    "test_google_account_inventory.py",
    "test_google_account_inventory_manager.py",
    "test_google_account_manager_cli.py",
    "test_google_account_subject_id.py",
    "test_google_inventory_authority_transaction.py",
    "test_google_inventory_desktop_client_registry.py",
    "test_google_inventory_oauth_leaf.py",
    "test_google_inventory_readonly_control_service.py",
    "test_google_inventory_readonly_control_transaction.py",
    "test_google_inventory_readonly_scan.py",
    "test_google_inventory_scan_lease.py",
    "test_google_inventory_schema3_migration.py",
    "test_google_inventory_schema_v2.py",
    "test_google_inventory_schema_v3.py",
    "test_google_inventory_store.py",
    "test_google_inventory_token_vault.py",
    "test_google_oauth_authorization.py",
    "test_google_oauth_session.py",
)


def _non_docstring_string_literals(path: Path) -> list[tuple[int, str]]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    docstring_lines: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef)) and node.body:
            first = node.body[0]
            if (
                isinstance(first, ast.Expr)
                and isinstance(first.value, ast.Constant)
                and isinstance(first.value.value, str)
            ):
                docstring_lines.add(first.lineno)
    return [
        (node.lineno, node.value)
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and node.lineno not in docstring_lines
    ]


def test_candidate_fixture_literals_use_explicit_synthetic_markers() -> None:
    """Identity- and synthetic-secret-shaped test values must never resemble live material."""

    marker = re.compile(
        r"(?<!synthetic-)(?:private|secret|subject|account|client|access|refresh|id|"
        r"authorization|inventory|operator|project|billing|key|token)" + r"-",
        re.IGNORECASE,
    )
    violations = [
        (path.name, line)
        for name in _CANDIDATE_TEST_FILES
        for path in (_ROOT / "tests" / name,)
        for line, value in _non_docstring_string_literals(path)
        if value not in _FIXED_NONFIXTURE_LITERALS and marker.search(value)
    ]

    assert not violations


class _Service:
    def __init__(self) -> None:
        self.calls: list[tuple[str, object | None]] = []

    def authorize(self) -> dict[str, str]:
        self.calls.append(("authorize", None))
        return {"status": "authorized"}

    def scan_plan(self) -> dict[str, object]:
        self.calls.append(("scan_plan", None))
        return {
            "status": "planned",
            "plan_reference": "plan-opaque-reference",
            "account_count": 1,
            "project_count": 2,
            "billing_account_count": 3,
            "service_count": 4,
            "key_count": 5,
            "changes": {"canonical_account": 1},
        }

    def apply(self, reference: object) -> dict[str, str]:
        self.calls.append(("apply", reference))
        return {"status": "applied"}


def test_parser_accepts_only_closed_inventory_actions() -> None:
    parser = cli.build_parser()

    authorized = parser.parse_args(["inventory", "authorize"])
    planned = parser.parse_args(["inventory", "scan", "--plan"])
    applied = parser.parse_args(["inventory", "--apply", "plan-opaque-reference"])

    assert (authorized.command, authorized.inventory_action) == (
        "inventory",
        "authorize",
    )
    assert (planned.command, planned.inventory_action, planned.plan) == (
        "inventory",
        "scan",
        True,
    )
    assert (applied.command, applied.inventory_action, applied.plan_reference) == (
        "inventory",
        None,
        "plan-opaque-reference",
    )

    for arguments in (
        ["oauth-authorize"],
        ["provision"],
        ["rename-existing"],
        ["inventory"],
        ["inventory", "scan"],
        ["inventory", "authorize", "--account", "blocked"],
        ["inventory", "scan", "--plan", "--synthetic-client-file", "blocked"],
        [
            "inventory",
            "--apply",
            "plan-opaque-reference",
            "--method",
            "blocked",
        ],
    ):
        with pytest.raises(SystemExit):
            parser.parse_args(arguments)


def test_single_private_dispatcher_owns_construction_and_closed_status_job(
    monkeypatch, capsys
) -> None:
    calls = []
    monkeypatch.setattr(cli, "GoogleInventoryReadonlyControlService", _Service)
    monkeypatch.setattr(
        cli,
        "_dispatch_inventory_job",
        lambda *arguments: calls.append(arguments) or {"status": "authorized"},
        raising=False,
    )

    assert cli.main(["inventory", "authorize"]) == 0
    assert cli.subject_id_main([]) == 0
    assert calls == [("authorize",), ("subject_status",)]
    capsys.readouterr()

    tree = ast.parse(Path(cli.__file__).read_text(encoding="utf-8"))
    owners = [
        function.name
        for function in tree.body
        if isinstance(function, ast.FunctionDef)
        for node in ast.walk(function)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "GoogleInventoryReadonlyControlService"
    ]
    assert owners == ["_dispatch_inventory_job"]


def test_dispatcher_rejects_unknown_jobs_before_constructing_service(monkeypatch):
    monkeypatch.setattr(
        cli,
        "GoogleInventoryReadonlyControlService",
        lambda: pytest.fail("invalid job constructed a service"),
    )
    with pytest.raises(Exception) as captured:
        cli._dispatch_inventory_job("unknown")
    assert getattr(captured.value, "code", None) == cli._REQUEST_INVALID


@pytest.mark.parametrize(
    ("arguments", "expected", "calls"),
    [
        (
            ["inventory", "authorize"],
            {"status": "authorized"},
            [("authorize", None)],
        ),
        (
            ["inventory", "scan", "--plan"],
            {
                "status": "planned",
                "plan_reference": "plan-opaque-reference",
                "account_count": 1,
                "project_count": 2,
                "billing_account_count": 3,
                "service_count": 4,
                "key_count": 5,
                "changes": {"canonical_account": 1},
            },
            [("scan_plan", None)],
        ),
        (
            ["inventory", "--apply", "plan-opaque-reference"],
            {"status": "applied"},
            [("apply", "plan-opaque-reference")],
        ),
    ],
)
def test_inventory_commands_only_project_authority_public_results(
    arguments, expected, calls, monkeypatch, capsys
) -> None:
    service = _Service()
    monkeypatch.setattr(cli, "GoogleInventoryReadonlyControlService", lambda: service)

    assert cli.main(arguments) == 0

    assert json.loads(capsys.readouterr().out) == expected
    assert service.calls == calls


def test_cli_fails_closed_when_authority_projection_has_sensitive_field(
    monkeypatch, capsys
) -> None:
    class SensitiveService(_Service):
        def scan_plan(self) -> dict[str, object]:
            result = super().scan_plan()
            result["unexpected_identity"] = "redacted-marker"
            return result

    monkeypatch.setattr(cli, "GoogleInventoryReadonlyControlService", SensitiveService)

    assert cli.main(["inventory", "scan", "--plan"]) == 1

    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.strip() == "inventory.readonly_control_unavailable"


def test_cli_prints_only_a_code_for_unrecognized_sensitive_argument(capsys) -> None:
    assert cli.main(["inventory", "authorize", "--unexpected", "blocked"]) == 1

    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.strip() == "inventory.readonly_control_request_invalid"


def test_goblin_uses_the_hive_cli_and_fails_closed_without_private_config() -> None:
    result = subprocess.run(
        [sys.executable, str(_SCRIPT), "inventory", "authorize"],
        cwd=_ROOT,
        env={"PYTHONPATH": str(_ROOT / "src")},
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 1
    assert result.stdout == ""
    assert result.stderr.strip() == "inventory.readonly_control_unavailable"


def test_manager_goblin_redacts_package_import_failure() -> None:
    result = subprocess.run(
        [sys.executable, str(_SCRIPT), "inventory", "authorize"],
        cwd=_ROOT,
        env={},
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 1
    assert result.stdout == ""
    assert result.stderr.strip() == "inventory.readonly_control_unavailable"
