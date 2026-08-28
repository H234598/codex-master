from __future__ import annotations

import pytest

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
