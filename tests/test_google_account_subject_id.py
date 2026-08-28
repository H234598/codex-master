from __future__ import annotations

from importlib.machinery import SourceFileLoader
from importlib.util import module_from_spec, spec_from_loader
from pathlib import Path
import stat
import tempfile
import unittest

from oauthlib.oauth2.rfc6749.parameters import parse_token_response
import yaml


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "google-account-subject-id"
LOADER = SourceFileLoader("google_account_subject_id", str(SCRIPT))
SPEC = spec_from_loader(LOADER.name, LOADER)
assert SPEC is not None
MODULE = module_from_spec(SPEC)
LOADER.exec_module(MODULE)


def slim_document() -> dict:
    return {
        "schema_version": 1,
        "google_accounts": [],
    }


def account_record(ref: str, email: str, subject_id: str | None) -> dict:
    return {
        "ref": ref,
        "login_email": email,
        "recovery_email": None,
        "subject_id": subject_id,
        "billing_accounts": [],
        "projects": [],
    }


class GoogleAccountSubjectIdTest(unittest.TestCase):
    def test_oidc_scopes_accept_google_canonical_email_scope(self) -> None:
        token = parse_token_response(
            '{"access_token":"test", "token_type":"Bearer", '
            '"scope":"https://www.googleapis.com/auth/userinfo.email openid"}',
            scope=MODULE.OIDC_SCOPES,
        )

        self.assertEqual(
            set(token["scope"]),
            {"openid", "https://www.googleapis.com/auth/userinfo.email"},
        )

    def test_upsert_is_idempotent_and_preserves_slim_schema(self) -> None:
        document = slim_document()
        self.assertEqual(
            MODULE.upsert_google_account(
                document,
                account_ref="google-nufker",
                subject_id="1234567890",
                login_email="nufker@example.com",
                label="Nufker Hauptaccount",
                replace=False,
            ),
            "created",
        )
        self.assertEqual(
            MODULE.upsert_google_account(
                document,
                account_ref="google-nufker",
                subject_id="1234567890",
                login_email="nufker@example.com",
                label=None,
                replace=False,
            ),
            "unchanged",
        )
        self.assertEqual(
            document["google_accounts"],
            [
                {
                    "ref": "google-nufker",
                    "login_email": "nufker@example.com",
                    "recovery_email": None,
                    "subject_id": "1234567890",
                    "billing_accounts": [],
                    "projects": [],
                    "label": "Nufker Hauptaccount",
                }
            ],
        )
        self.assertNotIn("display_name", document["google_accounts"][0])
        self.assertNotIn("resource_name", document["google_accounts"][0])

    def test_upsert_rejects_duplicate_subject_and_requires_replace(self) -> None:
        document = slim_document()
        document["google_accounts"] = [
            account_record("google-one", "one@example.com", "111"),
            account_record("google-two", "two@example.com", "222"),
        ]
        with self.assertRaisesRegex(MODULE.IdentityError, "already assigned"):
            MODULE.upsert_google_account(
                document,
                account_ref="google-three",
                subject_id="111",
                login_email="three@example.com",
                label=None,
                replace=False,
            )
        with self.assertRaisesRegex(MODULE.IdentityError, "--replace-subject"):
            MODULE.upsert_google_account(
                document,
                account_ref="google-two",
                subject_id="333",
                login_email="two@example.com",
                label=None,
                replace=False,
            )
        self.assertEqual(
            MODULE.upsert_google_account(
                document,
                account_ref="google-two",
                subject_id="333",
                login_email="two@example.com",
                label=None,
                replace=True,
            ),
            "updated",
        )

    def test_upsert_requires_matching_login_and_preserves_recovery_and_projects(self) -> None:
        account = account_record("google-four", "login@example.com", None)
        account["recovery_email"] = "recovery@example.com"
        account["projects"] = [
            {
                "ref": "the-hive-31",
                "billing_account_ref": None,
                "status": "active",
                "project_id": None,
                "project_number": None,
                "key_id": None,
                "key_uid": None,
                "secret": "synthetic-secret",
            }
        ]
        document = slim_document()
        document["google_accounts"] = [account]

        with self.assertRaisesRegex(MODULE.IdentityError, "does not match"):
            MODULE.upsert_google_account(
                document,
                account_ref="google-four",
                subject_id="444",
                login_email="recovery@example.com",
                label=None,
                replace=False,
            )
        self.assertIsNone(account["subject_id"])

        self.assertEqual(
            MODULE.upsert_google_account(
                document,
                account_ref="google-four",
                subject_id="444",
                login_email="login@example.com",
                label=None,
                replace=False,
            ),
            "updated",
        )
        self.assertEqual(account["recovery_email"], "recovery@example.com")
        self.assertEqual(account["projects"][0]["ref"], "the-hive-31")

    def test_private_yaml_round_trip_is_atomic_and_mode_0600(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_dir:
            path = Path(temporary_dir) / "api-token.yaml"
            path.write_text(yaml.safe_dump(slim_document(), sort_keys=False), encoding="utf-8")
            path.chmod(0o600)
            document = MODULE.load_private_yaml(path)
            MODULE.upsert_google_account(
                document,
                account_ref="google-private",
                subject_id="987654321",
                login_email="private@example.com",
                label=None,
                replace=False,
            )
            MODULE.atomic_write_private_yaml(path, document)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(MODULE.load_private_yaml(path)["google_accounts"][0]["subject_id"], "987654321")

    def test_private_file_validation_rejects_group_readable_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_dir:
            path = Path(temporary_dir) / "api-token.yaml"
            path.write_text(yaml.safe_dump(slim_document()), encoding="utf-8")
            path.chmod(0o640)
            with self.assertRaisesRegex(MODULE.IdentityError, "chmod 600"):
                MODULE.load_private_yaml(path)


if __name__ == "__main__":
    unittest.main()
