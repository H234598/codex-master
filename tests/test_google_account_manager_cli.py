from __future__ import annotations

import argparse
from pathlib import Path

import pytest

import codex_master.google_account_manager_cli as cli
from codex_master.google_account_manager_cli import build_parser


def test_cli_has_inventory_oauth_rename_and_dynamic_quota_only() -> None:
    parser = build_parser()

    oauth = parser.parse_args(
        [
            "oauth-authorize",
            "--account",
            "google-account-04",
            "--client-file",
            "/private/client.json",
            "--browser-profile",
            "/private/profile",
            "--browser-debug-port",
            "9241",
        ]
    )
    assert oauth.browser_debug_port == 9241

    inventory = parser.parse_args(
        ["inventory", "--account", "google-account-01", "--client-file", "/private/client.json"]
    )
    assert inventory.command == "inventory"

    provision = parser.parse_args(
        [
            "provision",
            "--account",
            "google-account-01",
            "--client-file",
            "/private/client.json",
            "--fill-to-quota",
            "--quota-remaining",
            "37",
        ]
    )
    assert provision.fill_to_quota is True
    assert provision.quota_remaining == 37

    with pytest.raises(SystemExit):
        parser.parse_args(
            [
                "provision",
                "--account",
                "google-account-01",
                "--client-file",
                "/private/client.json",
                "--fill-to",
                "10",
            ]
        )


def test_document_returns_the_store_document() -> None:
    document = {"google_accounts": []}

    class Store:
        def _read(self):
            return b"ignored", document

    assert cli._document(Store()) is document


def test_account_selects_exactly_one_matching_inventory_account() -> None:
    document = {"google_accounts": [{"ref": "one"}]}

    assert cli._account(document, "one") == {"ref": "one"}
    with pytest.raises(ValueError, match="inventory.account_invalid"):
        cli._account(document, "missing")


def test_api_builds_cloud_api_from_the_account_bound_access_token(monkeypatch) -> None:
    captured: list[object] = []

    class FakeApi:
        def __init__(self, token: str) -> None:
            captured.append(token)

    monkeypatch.setattr(cli, "load_access_token", lambda *args, **kwargs: "test-token")
    monkeypatch.setattr(cli, "GoogleCloudApi", FakeApi)

    assert isinstance(cli._api(object(), "one", Path("/private/client.json")), FakeApi)
    assert captured == ["test-token"]


def test_run_inventory_reports_only_subject_bound_project_counts(monkeypatch, capsys) -> None:
    class Store:
        pass

    class Api:
        def subject_id(self) -> str:
            return "subject-one"

        def search_projects(self):
            return [{"state": "ACTIVE"}, {"state": "DELETE_REQUESTED"}]

    monkeypatch.setattr(cli, "GoogleInventoryStore", Store)
    monkeypatch.setattr(cli, "_api", lambda *args: Api())
    monkeypatch.setattr(
        cli,
        "_document",
        lambda store: {"google_accounts": [{"ref": "one", "subject_id": "subject-one"}]},
    )
    result = cli.run(
        argparse.Namespace(command="inventory", account="one", client_file=Path("/private/client.json"))
    )

    assert result == 0
    assert capsys.readouterr().out.strip() == '{"account": "one", "active_project_count": 1, "project_count": 2}'


def test_main_converts_unexpected_failures_to_a_stable_exit_code(monkeypatch, capsys) -> None:
    monkeypatch.setattr(cli, "build_parser", lambda: object())
    monkeypatch.setattr(cli, "run", lambda arguments: (_ for _ in ()).throw(ValueError("private")))

    assert cli.main() == 1
    assert capsys.readouterr().err.strip() == "google.account_manager_failed"
