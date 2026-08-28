from __future__ import annotations

import json
import urllib.error

import pytest

from codex_master.google_cloud_api import (
    GoogleCloudApi,
    GoogleCloudApiError,
    _UrlLibTransport,
)


class FakeTransport:
    def __init__(self, responses: list[dict[str, object]]) -> None:
        self.responses = iter(responses)
        self.calls: list[tuple[str, str, dict[str, str], object]] = []

    def request(self, method, url, headers, body):
        self.calls.append((method, url, headers, body))
        return next(self.responses)


@pytest.mark.parametrize(
    ("status", "code"),
    [
        (400, "google.api_request_failed"),
        (401, "google.api_auth_failed"),
        (403, "google.api_auth_failed"),
        (404, "google.api_request_failed"),
        (408, "google.api_unavailable"),
        (409, "google.api_conflict"),
        (429, "google.api_quota_exhausted"),
        (500, "google.api_unavailable"),
        (503, "google.api_unavailable"),
    ],
)
def test_http_statuses_distinguish_transient_permanent_conflict_and_quota(
    status: int, code: str
) -> None:
    class Opener:
        def open(self, *_args, **_kwargs):
            raise urllib.error.HTTPError(
                "https://cloudresourcemanager.googleapis.com/v3/projects",
                status,
                "private provider text",
                None,
                None,
            )

    transport = _UrlLibTransport()
    transport._opener = Opener()

    with pytest.raises(GoogleCloudApiError, match=code):
        transport.request("POST", "https://example.invalid", {}, {})


def test_search_projects_is_bounded_and_paginated_without_token_rendering() -> None:
    transport = FakeTransport(
        [
            {"projects": [{"projectId": "one"}], "nextPageToken": "page-two"},
            {"projects": [{"projectId": "two"}]},
        ]
    )
    api = GoogleCloudApi._for_test("private-access-token", transport)

    projects = api.search_projects()

    assert [item["projectId"] for item in projects] == ["one", "two"]
    assert transport.calls[0][0] == "GET"
    assert transport.calls[0][3] is None
    assert transport.calls[1][1].endswith("?pageToken=page-two")
    assert "private-access-token" not in repr(api)


def test_mutation_payloads_are_allowlisted_and_key_is_restricted() -> None:
    transport = FakeTransport(
        [
            {"name": "operations/project-create"},
            {
                "done": True,
                "response": {
                    "projectId": "quietglow-aurora-a1b2c3",
                    "name": "projects/1",
                },
            },
            {"name": "operations/services"},
            {"done": True, "response": {}},
            {"name": "operations/key"},
            {
                "done": True,
                "response": {
                    "name": "projects/1/locations/global/keys/key-uid",
                    "uid": "key-uid",
                    "keyString": "private-key-secret",
                    "displayName": "Quietglow Aurorabay Key",
                },
            },
        ]
    )
    api = GoogleCloudApi._for_test("private-access-token", transport)

    project = api.create_project("quietglow-aurora-a1b2c3", "Quietglow Aurorabay")
    api.enable_required_services("123456")
    key = api.create_restricted_key("123456", "Quietglow Aurorabay Key")

    assert project["projectId"] == "quietglow-aurora-a1b2c3"
    assert key["keyString"] == "private-key-secret"
    key_body = transport.calls[4][3]
    assert key_body == {
        "displayName": "Quietglow Aurorabay Key",
        "restrictions": {
            "apiTargets": [{"service": "generativelanguage.googleapis.com"}]
        },
    }
    serialized_calls = json.dumps(transport.calls)
    assert "billing" not in serialized_calls.casefold()
    assert "iam" not in serialized_calls.casefold()


def test_userinfo_subject_must_be_nonempty() -> None:
    api = GoogleCloudApi._for_test(
        "private-access-token", FakeTransport([{"sub": "123"}])
    )
    assert api.subject_id() == "123"

    broken = GoogleCloudApi._for_test("private-access-token", FakeTransport([{}]))
    with pytest.raises(GoogleCloudApiError, match="google.api_response_invalid"):
        broken.subject_id()


def test_control_service_bootstrap_is_exact() -> None:
    transport = FakeTransport([{"done": True, "response": {}}])
    api = GoogleCloudApi._for_test("private-access-token", transport)

    api.enable_control_services("577074103233")

    assert transport.calls == [
        (
            "POST",
            "https://serviceusage.googleapis.com/v1/projects/577074103233/services:batchEnable",
            transport.calls[0][2],
            {
                "serviceIds": [
                    "serviceusage.googleapis.com",
                    "apikeys.googleapis.com",
                    "cloudresourcemanager.googleapis.com",
                ]
            },
        )
    ]


def test_api_surface_has_no_delete_billing_iam_or_quota_request_mutation() -> None:
    forbidden = (
        "delete_project",
        "set_billing_account",
        "set_iam_policy",
        "request_project_quota",
    )
    assert all(not hasattr(GoogleCloudApi, name) for name in forbidden)


def test_lookup_key_and_display_name_patch_are_exact() -> None:
    transport = FakeTransport(
        [
            {
                "parent": "projects/123456/locations/global",
                "name": "projects/123456/locations/global/keys/key-uid",
            },
            {
                "name": "operations/key-patch",
            },
            {
                "done": True,
                "response": {
                    "name": "projects/123456/locations/global/keys/key-uid",
                    "displayName": "Quietglow Aurorabay Key",
                },
            },
        ]
    )
    api = GoogleCloudApi._for_test("private-access-token", transport)

    lookup = api.lookup_key("private-key-secret")
    api.update_key_display_name(
        "projects/123456/locations/global/keys/key-uid",
        "Quietglow Aurorabay Key",
    )

    assert lookup["parent"] == "projects/123456/locations/global"
    assert transport.calls[0][1].endswith("?keyString=private-key-secret")
    assert transport.calls[0][0] == "GET"
    assert transport.calls[0][3] is None
    assert transport.calls[1][3] == {
        "name": "projects/123456/locations/global/keys/key-uid",
        "displayName": "Quietglow Aurorabay Key",
    }


def test_existing_key_secret_can_be_recovered_and_restricted_exactly() -> None:
    transport = FakeTransport(
        [
            {"keyString": "private-key-secret"},
            {
                "done": True,
                "response": {
                    "name": "projects/123456/locations/global/keys/key-uid",
                    "displayName": "Quietglow Aurorabay Key",
                },
            },
        ]
    )
    api = GoogleCloudApi._for_test("private-access-token", transport)
    key_name = "projects/123456/locations/global/keys/key-uid"

    assert api.get_key_string(key_name) == "private-key-secret"
    api.restrict_and_rename_key(key_name, "Quietglow Aurorabay Key")

    assert transport.calls[0][0:2] == (
        "GET",
        "https://apikeys.googleapis.com/v2/"
        "projects/123456/locations/global/keys/key-uid/keyString",
    )
    assert transport.calls[1][3] == {
        "name": key_name,
        "displayName": "Quietglow Aurorabay Key",
        "restrictions": {
            "apiTargets": [{"service": "generativelanguage.googleapis.com"}]
        },
    }
    assert "private-key-secret" not in repr(api)


def test_project_display_name_patch_waits_for_operation() -> None:
    transport = FakeTransport(
        [
            {"name": "operations/project-patch"},
            {
                "done": True,
                "response": {
                    "name": "projects/123456",
                    "displayName": "Quietglow Aurorabay",
                },
            },
        ]
    )
    api = GoogleCloudApi._for_test("private-access-token", transport)

    result = api.update_project_name("projects/123456", "Quietglow Aurorabay")

    assert result["displayName"] == "Quietglow Aurorabay"
    assert transport.calls[0][3] == {
        "name": "projects/123456",
        "displayName": "Quietglow Aurorabay",
    }
    assert transport.calls[1][1].endswith("/operations/project-patch")


def test_project_display_name_patch_accepts_inline_done_operation() -> None:
    api = GoogleCloudApi._for_test(
        "private-access-token",
        FakeTransport(
            [
                {
                    "done": True,
                    "response": {
                        "name": "projects/123456",
                        "displayName": "Quietglow Aurorabay",
                    },
                }
            ]
        ),
    )
    assert (
        api.update_project_name("projects/123456", "Quietglow Aurorabay")["displayName"]
        == "Quietglow Aurorabay"
    )
