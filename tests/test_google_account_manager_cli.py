from __future__ import annotations

import os
from types import SimpleNamespace
import time

import pytest

from codex_master import google_account_manager_cli as cli
from codex_master import server
from codex_master.google_account_manager_cli import _load_quota_evidence, build_parser
from codex_master.google_cloud_provisioner import GoogleCloudProvisionerError


INVENTORY_FINGERPRINT = "sha256:" + "a" * 64


def test_cli_has_inventory_oauth_rename_and_private_quota_evidence_only() -> None:
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
        [
            "inventory",
            "--account",
            "google-account-01",
            "--client-file",
            "/private/client.json",
        ]
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
            "--quota-evidence-file",
            "/private/quota.json",
        ]
    )
    assert provision.fill_to_quota is True
    assert provision.quota_evidence_file.as_posix() == "/private/quota.json"

    with pytest.raises(SystemExit):
        parser.parse_args(
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


def _private_evidence_file(tmp_path, payload: str):
    path = tmp_path / "quota.json"
    path.write_text(payload, encoding="utf-8")
    path.chmod(0o600)
    return path


def test_private_quota_evidence_file_loads_exact_schema(tmp_path) -> None:
    path = _private_evidence_file(
        tmp_path,
        '{"remaining":23,"observed_at":"2026-08-28T12:00:00Z",'
        '"source":"cloudresourcemanager","account_ref":"google-account-01",'
        '"inventory_generation":7,"inventory_fingerprint":"sha256:' + "a" * 64 + '"}',
    )

    evidence = _load_quota_evidence(path)

    assert evidence.remaining == 23
    assert evidence.inventory_generation == 7
    assert "secret" not in repr(evidence).casefold()


@pytest.mark.parametrize(
    "payload",
    [
        '{"remaining":1,"remaining":2,"observed_at":"2026-08-28T12:00:00Z",'
        '"source":"cloudresourcemanager","account_ref":"google-account-01",'
        '"inventory_generation":7,"inventory_fingerprint":"sha256:' + "a" * 64 + '"}',
        '{"remaining":NaN,"observed_at":"2026-08-28T12:00:00Z",'
        '"source":"cloudresourcemanager","account_ref":"google-account-01",'
        '"inventory_generation":7,"inventory_fingerprint":"sha256:' + "a" * 64 + '"}',
        '{"remaining":null,"observed_at":"2026-08-28T12:00:00Z",'
        '"source":"cloudresourcemanager","account_ref":"google-account-01",'
        '"inventory_generation":7,"inventory_fingerprint":"sha256:' + "a" * 64 + '"}',
        '{"remaining":1,"observed_at":"2026-08-28T12:00:00Z",'
        '"source":"cloudresourcemanager","account_ref":"google-account-01",'
        '"inventory_generation":7,"inventory_fingerprint":"sha256:'
        + "a" * 64
        + '","access_token":"private-secret"}',
    ],
)
def test_private_quota_evidence_file_rejects_ambiguous_or_extra_data(
    tmp_path, payload: str
) -> None:
    path = _private_evidence_file(tmp_path, payload)

    with pytest.raises(
        GoogleCloudProvisionerError, match="quota.evidence_file_invalid"
    ):
        _load_quota_evidence(path)


def test_private_quota_evidence_file_rejects_unsafe_file_and_oversize(tmp_path) -> None:
    unsafe = _private_evidence_file(tmp_path, "{}")
    unsafe.chmod(0o644)
    with pytest.raises(
        GoogleCloudProvisionerError, match="quota.evidence_file_invalid"
    ):
        _load_quota_evidence(unsafe)

    target = _private_evidence_file(tmp_path, "{}")
    link = tmp_path / "quota-link.json"
    os.symlink(target, link)
    with pytest.raises(
        GoogleCloudProvisionerError, match="quota.evidence_file_invalid"
    ):
        _load_quota_evidence(link)

    oversized = _private_evidence_file(tmp_path, " " * 16_385)
    with pytest.raises(
        GoogleCloudProvisionerError, match="quota.evidence_file_invalid"
    ):
        _load_quota_evidence(oversized)


def test_cli_binds_evidence_to_current_manager_generation_before_provider_search(
    tmp_path, monkeypatch
) -> None:
    path = _private_evidence_file(
        tmp_path,
        json_payload(
            remaining=1,
            observed_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            inventory_generation=2,
        ),
    )

    class Store:
        def _read(self):
            return b"", {
                "google_accounts": [
                    {
                        "ref": "google-account-01",
                        "subject_id": "subject-one",
                    }
                ]
            }

    class Api:
        searches = 0

        def subject_id(self):
            return "subject-one"

        def search_projects(self):
            self.searches += 1
            return []

    class Manager:
        closed = False

        def reload(self):
            return None

        def _snapshot_for_internal_use(self):
            account = SimpleNamespace(subject_id="subject-one")
            return SimpleNamespace(
                generation=1,
                content_fingerprint=INVENTORY_FINGERPRINT,
                by_account_ref={"google-account-01": account},
            )

        def close(self):
            self.closed = True

    api = Api()
    manager = Manager()
    monkeypatch.setattr(cli, "GoogleInventoryStore", Store)
    monkeypatch.setattr(cli, "_api", lambda *_: api)
    monkeypatch.setattr(cli, "GoogleAccountInventoryManager", lambda: manager)
    arguments = build_parser().parse_args(
        [
            "provision",
            "--account",
            "google-account-01",
            "--client-file",
            "/private/client.json",
            "--fill-to-quota",
            "--quota-evidence-file",
            str(path),
        ]
    )

    with pytest.raises(
        GoogleCloudProvisionerError, match="quota.evidence_generation_mismatch"
    ):
        cli.run(arguments)

    assert api.searches == 0
    assert manager.closed is True


def test_cli_plans_from_manager_snapshot_without_second_inventory_read(
    tmp_path, monkeypatch, capsys
) -> None:
    path = _private_evidence_file(
        tmp_path,
        json_payload(
            remaining=1,
            observed_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            inventory_generation=1,
        ),
    )

    class Store:
        def _read(self):
            raise AssertionError("raw inventory reread")

    class Api:
        def subject_id(self):
            return "subject-one"

        def search_projects(self):
            return []

    account = SimpleNamespace(
        ref="google-account-01", subject_id="subject-one", projects=()
    )
    snapshot = SimpleNamespace(
        generation=1,
        content_fingerprint=INVENTORY_FINGERPRINT,
        accounts=(account,),
        by_account_ref={"google-account-01": account},
    )

    class Manager:
        closed = False

        def reload(self):
            return None

        def _snapshot_for_internal_use(self):
            return snapshot

        def close(self):
            self.closed = True

    manager = Manager()
    monkeypatch.setattr(cli, "GoogleInventoryStore", Store)
    monkeypatch.setattr(cli, "_api", lambda *_: Api())
    monkeypatch.setattr(cli, "GoogleAccountInventoryManager", lambda: manager)
    arguments = build_parser().parse_args(
        [
            "provision",
            "--account",
            "google-account-01",
            "--client-file",
            "/private/client.json",
            "--fill-to-quota",
            "--quota-evidence-file",
            str(path),
        ]
    )

    assert cli.run(arguments) == 2
    assert '"planned_projects": 1' in capsys.readouterr().out
    assert manager.closed is True


def test_untrusted_private_evidence_blocks_apply_before_token_factory(
    tmp_path, monkeypatch, capsys
) -> None:
    path = _private_evidence_file(
        tmp_path,
        json_payload(
            remaining=1,
            observed_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            inventory_generation=1,
        ),
    )
    inventory_fingerprint = "sha256:" + "a" * 64
    account = SimpleNamespace(
        ref="google-account-01", subject_id="subject-one", projects=()
    )
    snapshot = SimpleNamespace(
        generation=1,
        content_fingerprint=inventory_fingerprint,
        accounts=(account,),
        by_account_ref={"google-account-01": account},
    )

    class Store:
        def __init__(self):
            self.mutations = 0

        def _read(self):
            return b"", {
                "google_accounts": [
                    {
                        "ref": "google-account-01",
                        "subject_id": "subject-one",
                        "projects": [],
                    }
                ]
            }

        def atomic_update(self, transform):
            self.mutations += 1
            raise AssertionError("untrusted mutation")

    class Api:
        creates = 0

        def subject_id(self):
            return "subject-one"

        def search_projects(self):
            return []

        def create_project(self, *_):
            self.creates += 1
            return {"name": "projects/123"}

    class Manager:
        def reload(self):
            return None

        def _snapshot_for_internal_use(self):
            return snapshot

        def close(self):
            return None

    store = Store()
    api = Api()

    def mutating_token_factory(store_arg, *, account_ref, client_file):
        store_arg.mutations += 1
        return "opaque"

    monkeypatch.setattr(cli, "GoogleInventoryStore", lambda: store)
    monkeypatch.setattr(cli, "load_access_token", mutating_token_factory)
    monkeypatch.setattr(cli, "GoogleCloudApi", lambda token: api)
    monkeypatch.setattr(cli, "GoogleAccountInventoryManager", Manager)
    arguments = build_parser().parse_args(
        [
            "provision",
            "--account",
            "google-account-01",
            "--client-file",
            "/private/client.json",
            "--fill-to-quota",
            "--quota-evidence-file",
            str(path),
            "--yes",
        ]
    )

    with pytest.raises(GoogleCloudProvisionerError, match="quota_evidence_untrusted"):
        cli.run(arguments)

    assert capsys.readouterr().out == ""
    assert api.creates == 0
    assert store.mutations == 0


def json_payload(*, remaining: int, observed_at: str, inventory_generation: int) -> str:
    return (
        f'{{"remaining":{remaining},"observed_at":"{observed_at}",'
        '"source":"cloudresourcemanager","account_ref":"google-account-01",'
        f'"inventory_generation":{inventory_generation},'
        f'"inventory_fingerprint":"{INVENTORY_FINGERPRINT}"}}'
    )


def test_masterjet_google_inventory_bypasses_legacy_cli_adapter(monkeypatch) -> None:
    from test_admin_service import principal, service_at

    service, _owners = service_at()
    monkeypatch.setattr(
        server,
        "_MASTERJET_ADMIN_BINDING",
        (service, principal("fleet.read")),
    )
    monkeypatch.setattr(
        cli,
        "run",
        lambda _arguments: (_ for _ in ()).throw(AssertionError("legacy CLI used")),
    )

    result = server.call_validated_tool("fleet_google_inventory", {})

    assert result["accounts"][0]["ref"] == "google-one"
