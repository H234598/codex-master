"""CLI for isolated Google account inventory and quota provisioning."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import time
from typing import cast

from .google_account_inventory import GoogleAccountInventoryError
from .google_account_inventory import _read_private_inventory_bytes
from .google_account_inventory_manager import (
    GoogleAccountInventoryManager,
    _GoogleAccountInventorySnapshotV1,
)
from .google_cloud_api import GoogleCloudApi
from .google_cloud_inventory import rename_and_reconcile_existing_projects
from .google_cloud_provisioner import (
    GoogleCloudProvisionerError,
    GoogleQuotaEvidenceV1,
    _validate_quota_evidence,
    build_fill_to_quota_plan,
)
from .google_inventory_store import GoogleInventoryStore
from .google_oauth_session import authorize_google_account, load_access_token


_QUOTA_EVIDENCE_FIELDS = frozenset(
    {
        "remaining",
        "observed_at",
        "source",
        "account_ref",
        "inventory_generation",
        "inventory_fingerprint",
    }
)
_MAX_QUOTA_EVIDENCE_BYTES = 16 * 1024


def _common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--account", required=True)
    parser.add_argument("--client-file", required=True, type=Path)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="google-account-manager")
    commands = parser.add_subparsers(dest="command", required=True)

    oauth = commands.add_parser("oauth-authorize")
    _common(oauth)
    oauth.add_argument("--browser-profile", required=True, type=Path)
    oauth.add_argument("--browser-debug-port", type=int)

    inventory = commands.add_parser("inventory")
    _common(inventory)

    rename = commands.add_parser("rename-existing")
    _common(rename)
    rename.add_argument("--control-project-id", action="append", default=[])
    rename.add_argument("--yes", action="store_true")

    provision = commands.add_parser("provision")
    _common(provision)
    provision.add_argument("--fill-to-quota", action="store_true", required=True)
    provision.add_argument("--quota-evidence-file", type=Path, required=True)
    provision.add_argument("--yes", action="store_true")
    return parser


def _document(store: GoogleInventoryStore) -> dict[str, object]:
    return store._read()[1]


def _account(document: dict[str, object], ref: str) -> dict[str, object]:
    accounts = document.get("google_accounts")
    if type(accounts) is not list:
        raise ValueError("inventory.invalid")
    found = [item for item in accounts if type(item) is dict and item.get("ref") == ref]
    if len(found) != 1:
        raise ValueError("inventory.account_invalid")
    return found[0]


def _api(
    store: GoogleInventoryStore, account: str, client_file: Path
) -> GoogleCloudApi:
    return GoogleCloudApi(
        load_access_token(store, account_ref=account, client_file=client_file)
    )


def _strict_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result


def _reject_nonfinite(_: str) -> object:
    raise ValueError


def _load_quota_evidence(path: Path) -> GoogleQuotaEvidenceV1:
    try:
        raw = _read_private_inventory_bytes(path)
        if not 0 < len(raw) <= _MAX_QUOTA_EVIDENCE_BYTES or b"\x00" in raw:
            raise ValueError
        parsed = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_strict_json_object,
            parse_constant=_reject_nonfinite,
        )
        if type(parsed) is not dict or set(parsed) != _QUOTA_EVIDENCE_FIELDS:
            raise ValueError
        evidence = GoogleQuotaEvidenceV1(
            remaining=parsed["remaining"],
            observed_at=parsed["observed_at"],
            source=parsed["source"],
            account_ref=parsed["account_ref"],
            inventory_generation=parsed["inventory_generation"],
            inventory_fingerprint=parsed["inventory_fingerprint"],
        )
        _validate_quota_evidence(
            evidence,
            account_ref=evidence.account_ref,
            inventory_generation=evidence.inventory_generation,
            inventory_fingerprint=evidence.inventory_fingerprint,
            now=evidence.observed_at,
        )
        return evidence
    except (
        GoogleAccountInventoryError,
        GoogleCloudProvisionerError,
        UnicodeError,
        ValueError,
        TypeError,
    ):
        raise GoogleCloudProvisionerError("quota.evidence_file_invalid") from None


def _provision_document(
    snapshot: _GoogleAccountInventorySnapshotV1,
) -> dict[str, object]:
    return {
        "google_accounts": [
            {
                "ref": account.ref,
                "subject_id": account.subject_id,
                "projects": [
                    {
                        "ref": project.ref,
                        "purpose": project.purpose,
                        "project_name": project.project_name,
                        "status": project.status,
                        "project_id": project.project_id,
                        "project_number": project.project_number,
                        "key_name": project.key_name,
                    }
                    for project in account.projects
                ],
            }
            for account in snapshot.accounts
        ]
    }


def run(arguments: argparse.Namespace) -> int:
    store = GoogleInventoryStore()
    if arguments.command == "oauth-authorize":
        receipt = authorize_google_account(
            store,
            account_ref=arguments.account,
            client_file=arguments.client_file,
            browser_profile=arguments.browser_profile,
            browser_debug_port=arguments.browser_debug_port,
        )
        print(
            json.dumps(
                {
                    "account": receipt.account_ref,
                    "subject_bound": receipt.subject_bound,
                    "refresh_token_stored": receipt.refresh_token_stored,
                },
                sort_keys=True,
            )
        )
        return 0

    api = _api(store, arguments.account, arguments.client_file)
    if arguments.command == "provision":
        evidence = _load_quota_evidence(arguments.quota_evidence_file)
        manager = GoogleAccountInventoryManager()
        try:
            manager.reload()
            snapshot = manager._snapshot_for_internal_use()
            generation = snapshot.generation
            inventory_fingerprint = snapshot.content_fingerprint
            try:
                account = snapshot.by_account_ref[arguments.account]
            except KeyError:
                raise GoogleCloudProvisionerError(
                    "provisioner.account_invalid"
                ) from None
            subject = account.subject_id
            if type(subject) is not str or not subject or api.subject_id() != subject:
                raise GoogleCloudProvisionerError("provisioner.subject_mismatch")
            now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            _validate_quota_evidence(
                evidence,
                account_ref=arguments.account,
                inventory_generation=generation,
                inventory_fingerprint=inventory_fingerprint,
                now=now,
            )
            cloud_projects = api.search_projects()
            plan = build_fill_to_quota_plan(
                _provision_document(snapshot),
                account_ref=arguments.account,
                expected_subject_id=subject,
                quota_evidence=evidence,
                inventory_generation=generation,
                inventory_fingerprint=inventory_fingerprint,
                now=now,
                visible_project_names={
                    cast(str, item["displayName"])
                    for item in cloud_projects
                    if type(item.get("displayName")) is str
                },
                reserved_project_ids={
                    cast(str, item["projectId"])
                    for item in cloud_projects
                    if type(item.get("projectId")) is str
                },
            )
            print(
                json.dumps(
                    {
                        "account": arguments.account,
                        "planned_projects": len(plan.projects),
                        "projects": [
                            {
                                "ref": item.ref,
                                "project_name": item.project_name,
                                "project_id": item.project_id,
                                "key_name": item.key_display_name,
                            }
                            for item in plan.projects
                        ],
                        "fingerprint": plan.fingerprint,
                        "execute": False,
                        "apply_blocked_reason": "quota_evidence_untrusted",
                    },
                    sort_keys=True,
                )
            )
            if arguments.yes:
                raise GoogleCloudProvisionerError("quota_evidence_untrusted")
            return 2
        finally:
            manager.close()

    document = _document(store)
    account = _account(document, arguments.account)
    subject = account.get("subject_id")
    if type(subject) is not str or not subject or api.subject_id() != subject:
        raise ValueError("inventory.subject_mismatch")

    if arguments.command == "inventory":
        projects = api.search_projects()
        print(
            json.dumps(
                {
                    "account": arguments.account,
                    "project_count": len(projects),
                    "active_project_count": sum(
                        item.get("state") == "ACTIVE" for item in projects
                    ),
                },
                sort_keys=True,
            )
        )
        return 0

    if arguments.command == "rename-existing":
        projects = api.search_projects()
        preview = {
            "account": arguments.account,
            "active_projects_to_rename": sum(
                item.get("state") == "ACTIVE" for item in projects
            ),
            "execute": bool(arguments.yes),
        }
        print(json.dumps(preview, sort_keys=True))
        if not arguments.yes:
            return 2
        receipt = rename_and_reconcile_existing_projects(
            document,
            account_ref=arguments.account,
            expected_subject_id=subject,
            api=api,
            store=store,
            control_project_ids=set(arguments.control_project_id),
        )
        print(
            json.dumps(
                {
                    "projects_renamed": receipt.projects_renamed,
                    "keys_renamed": receipt.keys_renamed,
                },
                sort_keys=True,
            )
        )
        return 0

    raise ValueError("command.invalid")


def main() -> int:
    try:
        return run(build_parser().parse_args())
    except Exception as error:
        code = getattr(error, "code", None)
        print(
            code if type(code) is str else "google.account_manager_failed",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
