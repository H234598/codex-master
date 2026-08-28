"""Small allowlisted Google Cloud REST client for inventory and provisioning."""

from __future__ import annotations

import json
import time
from typing import Callable, Protocol
import urllib.error
import urllib.parse
import urllib.request


_RESOURCE_MANAGER = "https://cloudresourcemanager.googleapis.com/v3"
_SERVICE_USAGE = "https://serviceusage.googleapis.com/v1"
_API_KEYS = "https://apikeys.googleapis.com/v2"
_USERINFO = "https://openidconnect.googleapis.com/v1/userinfo"
_REQUIRED_SERVICES = (
    "serviceusage.googleapis.com",
    "apikeys.googleapis.com",
    "generativelanguage.googleapis.com",
)
_CONTROL_SERVICES = (
    "serviceusage.googleapis.com",
    "apikeys.googleapis.com",
    "cloudresourcemanager.googleapis.com",
)


class GoogleCloudApiError(Exception):
    __slots__ = ("code",)

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)

    def __repr__(self) -> str:
        return f"GoogleCloudApiError({self.code!r})"


class _Transport(Protocol):
    def request(
        self, method: str, url: str, headers: dict[str, str], body: object
    ) -> dict[str, object]: ...


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class _UrlLibTransport:
    __slots__ = ("_opener",)

    def __init__(self) -> None:
        self._opener = urllib.request.build_opener(_NoRedirect())

    def request(
        self, method: str, url: str, headers: dict[str, str], body: object
    ) -> dict[str, object]:
        payload = None
        if body is not None:
            payload = json.dumps(body, separators=(",", ":")).encode("utf-8")
        request = urllib.request.Request(
            url, data=payload, headers=headers, method=method
        )
        try:
            with self._opener.open(request, timeout=30) as response:
                raw = response.read(1_048_577)
                if len(raw) > 1_048_576:
                    raise GoogleCloudApiError("google.api_response_invalid")
        except GoogleCloudApiError:
            raise
        except urllib.error.HTTPError as error:
            if error.code in {401, 403}:
                raise GoogleCloudApiError("google.api_auth_failed") from None
            if error.code == 409:
                raise GoogleCloudApiError("google.api_conflict") from None
            if error.code == 429:
                raise GoogleCloudApiError("google.api_quota_exhausted") from None
            raise GoogleCloudApiError("google.api_request_failed") from None
        except (OSError, urllib.error.URLError):
            raise GoogleCloudApiError("google.api_unavailable") from None
        try:
            decoded = json.loads(raw)
        except (UnicodeError, json.JSONDecodeError):
            raise GoogleCloudApiError("google.api_response_invalid") from None
        if type(decoded) is not dict:
            raise GoogleCloudApiError("google.api_response_invalid")
        return decoded


class GoogleCloudApi:
    __slots__ = ("_access_token", "_transport", "_sleep")

    def __init__(self, access_token: str) -> None:
        if type(access_token) is not str or not access_token:
            raise GoogleCloudApiError("google.api_auth_failed")
        self._access_token = access_token
        self._transport: _Transport = _UrlLibTransport()
        self._sleep: Callable[[float], None] = time.sleep

    @classmethod
    def _for_test(cls, access_token: str, transport: _Transport) -> GoogleCloudApi:
        api = cls.__new__(cls)
        api._access_token = access_token
        api._transport = transport
        api._sleep = lambda _: None
        return api

    def __repr__(self) -> str:
        return "GoogleCloudApi()"

    def _request(self, method: str, url: str, body: object = None) -> dict[str, object]:
        return self._transport.request(
            method,
            url,
            {
                "Authorization": "Bearer " + self._access_token,
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
            body,
        )

    def _wait_operation(self, name: object, base: str) -> dict[str, object]:
        if type(name) is not str or not name or not name.startswith("operations/"):
            raise GoogleCloudApiError("google.api_response_invalid")
        for _ in range(150):
            operation = self._request("GET", f"{base}/{name}")
            if operation.get("done") is True:
                if "error" in operation:
                    raise GoogleCloudApiError("google.api_operation_failed")
                response = operation.get("response", {})
                if type(response) is not dict:
                    raise GoogleCloudApiError("google.api_response_invalid")
                return response
            self._sleep(2)
        raise GoogleCloudApiError("google.api_operation_timeout")

    def _operation_response(
        self, operation: dict[str, object], base: str
    ) -> dict[str, object]:
        if operation.get("done") is True:
            if "error" in operation:
                raise GoogleCloudApiError("google.api_operation_failed")
            response = operation.get("response", {})
            if type(response) is not dict:
                raise GoogleCloudApiError("google.api_response_invalid")
            return response
        return self._wait_operation(operation.get("name"), base)

    def subject_id(self) -> str:
        result = self._request("GET", _USERINFO)
        subject = result.get("sub")
        if type(subject) is not str or not subject:
            raise GoogleCloudApiError("google.api_response_invalid")
        return subject

    def search_projects(self) -> list[dict[str, object]]:
        projects: list[dict[str, object]] = []
        page_token: str | None = None
        for _ in range(100):
            url = f"{_RESOURCE_MANAGER}/projects:search"
            if page_token is not None:
                url += "?" + urllib.parse.urlencode({"pageToken": page_token})
            page = self._request("GET", url)
            items = page.get("projects", [])
            if type(items) is not list or any(type(item) is not dict for item in items):
                raise GoogleCloudApiError("google.api_response_invalid")
            projects.extend(items)
            if len(projects) > 10_000:
                raise GoogleCloudApiError("google.api_response_invalid")
            token = page.get("nextPageToken")
            if token is None:
                return projects
            if type(token) is not str or not token:
                raise GoogleCloudApiError("google.api_response_invalid")
            page_token = token
        raise GoogleCloudApiError("google.api_response_invalid")

    def create_project(self, project_id: str, project_name: str) -> dict[str, object]:
        operation = self._request(
            "POST",
            f"{_RESOURCE_MANAGER}/projects",
            {"projectId": project_id, "displayName": project_name},
        )
        return self._operation_response(operation, _RESOURCE_MANAGER)

    def update_project_name(
        self, resource_name: str, project_name: str
    ) -> dict[str, object]:
        operation = self._request(
            "PATCH",
            f"{_RESOURCE_MANAGER}/{resource_name}?updateMask=displayName",
            {"name": resource_name, "displayName": project_name},
        )
        return self._operation_response(operation, _RESOURCE_MANAGER)

    def enable_required_services(self, project_number: str) -> dict[str, object]:
        operation = self._request(
            "POST",
            f"{_SERVICE_USAGE}/projects/{project_number}/services:batchEnable",
            {"serviceIds": list(_REQUIRED_SERVICES)},
        )
        return self._operation_response(operation, _SERVICE_USAGE)

    def enable_control_services(self, project_number: str) -> dict[str, object]:
        operation = self._request(
            "POST",
            f"{_SERVICE_USAGE}/projects/{project_number}/services:batchEnable",
            {"serviceIds": list(_CONTROL_SERVICES)},
        )
        return self._operation_response(operation, _SERVICE_USAGE)

    def create_restricted_key(
        self, project_number: str, display_name: str
    ) -> dict[str, object]:
        operation = self._request(
            "POST",
            f"{_API_KEYS}/projects/{project_number}/locations/global/keys",
            {
                "displayName": display_name,
                "restrictions": {
                    "apiTargets": [{"service": "generativelanguage.googleapis.com"}]
                },
            },
        )
        return self._operation_response(operation, _API_KEYS)

    def lookup_key(self, key_string: str) -> dict[str, object]:
        query = urllib.parse.urlencode({"keyString": key_string})
        return self._request("GET", f"{_API_KEYS}/keys:lookupKey?{query}")

    def get_key_string(self, key_name: str) -> str:
        result = self._request("GET", f"{_API_KEYS}/{key_name}/keyString")
        key_string = result.get("keyString")
        if type(key_string) is not str or not key_string:
            raise GoogleCloudApiError("google.api_response_invalid")
        return key_string

    def update_key_display_name(
        self, key_name: str, display_name: str
    ) -> dict[str, object]:
        operation = self._request(
            "PATCH",
            f"{_API_KEYS}/{key_name}?updateMask=displayName",
            {"name": key_name, "displayName": display_name},
        )
        return self._operation_response(operation, _API_KEYS)

    def restrict_and_rename_key(
        self, key_name: str, display_name: str
    ) -> dict[str, object]:
        operation = self._request(
            "PATCH",
            f"{_API_KEYS}/{key_name}?updateMask=displayName,restrictions",
            {
                "name": key_name,
                "displayName": display_name,
                "restrictions": {
                    "apiTargets": [{"service": "generativelanguage.googleapis.com"}]
                },
            },
        )
        return self._operation_response(operation, _API_KEYS)

    def list_keys(self, project_number: str) -> list[dict[str, object]]:
        page = self._request(
            "GET", f"{_API_KEYS}/projects/{project_number}/locations/global/keys"
        )
        keys = page.get("keys", [])
        if type(keys) is not list or any(type(item) is not dict for item in keys):
            raise GoogleCloudApiError("google.api_response_invalid")
        return keys

    def list_enabled_services(self, project_number: str) -> list[dict[str, object]]:
        page = self._request(
            "GET",
            f"{_SERVICE_USAGE}/projects/{project_number}/services?filter=state%3AENABLED",
        )
        services = page.get("services", [])
        if type(services) is not list or any(
            type(item) is not dict for item in services
        ):
            raise GoogleCloudApiError("google.api_response_invalid")
        return services
