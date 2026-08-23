from __future__ import annotations

from dataclasses import FrozenInstanceError, asdict, is_dataclass
import builtins
import os
import pickle
from pathlib import Path
import socket
import time
from traceback import TracebackException
from typing import Callable
import webbrowser

import pytest

import codex_master.google_oauth_authorization as policy
from codex_master.google_oauth_authorization import (
    GoogleOAuthAuthorizationError,
    GoogleOAuthAuthorizationProfileV1,
    GoogleOAuthOperationV1,
    GoogleOAuthProfileIdV1,
    resolve_google_oauth_profile_v1,
)


EXPECTED_SCOPES = (
    "cloud-billing.readonly",
    "cloud-platform.read-only",
    "email",
    "openid",
)
EXPECTED_OPERATIONS = (
    "keys.get",
    "keys.list",
    "keys.lookupKey",
    "projects.get",
    "projects.getBillingInfo",
    "projects.search",
)
EXPECTED_SCOPE_FINGERPRINT = (
    "sha256:9b2a7ff6966db417c590bbaae896036309e4391f414c7c93cf727873ed7d7e7f"
)
READONLY_PROFILE = GoogleOAuthProfileIdV1.INVENTORY_READONLY


class StringSubclass(str):
    pass


class ExplodingComparison:
    def __eq__(self, other: object) -> bool:
        raise AssertionError("foreign equality must not run")

    def __hash__(self) -> int:
        raise AssertionError("foreign hashing must not run")


def resolve(operation: GoogleOAuthOperationV1) -> GoogleOAuthAuthorizationProfileV1:
    return resolve_google_oauth_profile_v1(READONLY_PROFILE, operation)


_POLICY_SOURCE = Path(policy.__file__).resolve()


def _capture_failure(call: Callable[[], object]) -> Exception:
    try:
        call()
    except (GoogleOAuthAuthorizationError, TypeError) as error:
        return error
    raise AssertionError("expected policy failure")


def _exception_graph(root: BaseException) -> tuple[BaseException, ...]:
    seen: set[int] = set()
    pending = [root]
    graph: list[BaseException] = []
    while pending:
        error = pending.pop()
        if id(error) in seen:
            continue
        seen.add(id(error))
        graph.append(error)
        if error.__cause__ is not None:
            pending.append(error.__cause__)
        if error.__context__ is not None:
            pending.append(error.__context__)
        pending.extend(getattr(error, "exceptions", ()))
    return tuple(graph)


def _safe_repr(value: object) -> str:
    if isinstance(value, GoogleOAuthAuthorizationError) and not hasattr(value, "code"):
        return object.__repr__(value)
    return repr(value)


def _assert_failure_graph_is_redacted(error: Exception, marker: str) -> None:
    for graph_error in _exception_graph(error):
        rendered = (
            repr(graph_error),
            str(graph_error),
            repr(graph_error.args),
            pickle.dumps(graph_error).decode("latin1"),
        )
        assert all(marker not in value for value in rendered)

        traceback = graph_error.__traceback__
        while traceback is not None:
            frame = traceback.tb_frame
            if Path(frame.f_code.co_filename).resolve() == _POLICY_SOURCE:
                assert all(
                    marker not in _safe_repr(value) for value in frame.f_locals.values()
                )
            traceback = traceback.tb_next

        captured = TracebackException.from_exception(
            graph_error,
            capture_locals=True,
        )
        for summary in captured.stack:
            if Path(summary.filename).resolve() == _POLICY_SOURCE:
                assert all(
                    marker not in value for value in (summary.locals or {}).values()
                )


@pytest.mark.parametrize("argument", ("profile_id", "operation"))
def test_i1_invalid_type_inputs_leave_no_marker_in_production_traceback(
    argument: str,
) -> None:
    marker = f"i1-invalid-{argument}-access-token"
    if argument == "profile_id":
        error = _capture_failure(
            lambda: resolve_google_oauth_profile_v1(
                StringSubclass(marker), GoogleOAuthOperationV1.PROJECTS_SEARCH
            )
        )
    else:
        error = _capture_failure(
            lambda: resolve_google_oauth_profile_v1(
                READONLY_PROFILE, StringSubclass(marker)
            )
        )

    assert isinstance(error, GoogleOAuthAuthorizationError)
    assert error.code == "credential.oauth_request_invalid"
    _assert_failure_graph_is_redacted(error, marker)


def test_i1_unknown_profile_leaves_no_marker_in_production_traceback() -> None:
    marker = "i1-unknown-profile-refresh-token"
    error = _capture_failure(
        lambda: resolve_google_oauth_profile_v1(
            marker, GoogleOAuthOperationV1.PROJECTS_SEARCH
        )
    )

    assert isinstance(error, GoogleOAuthAuthorizationError)
    assert error.code == "credential.oauth_profile_unknown"
    _assert_failure_graph_is_redacted(error, marker)


def test_i1_forbidden_operation_leaves_no_marker_in_production_traceback() -> None:
    marker = "i1-forbidden-operation-client-secret"
    error = _capture_failure(
        lambda: resolve_google_oauth_profile_v1(READONLY_PROFILE, marker)
    )

    assert isinstance(error, GoogleOAuthAuthorizationError)
    assert error.code == "credential.oauth_operation_forbidden"
    _assert_failure_graph_is_redacted(error, marker)


def test_i1_direct_invalid_error_code_leaves_no_marker_in_traceback() -> None:
    marker = "i1-invalid-error-code-refresh-token"
    error = _capture_failure(lambda: GoogleOAuthAuthorizationError(marker))

    assert type(error) is TypeError
    _assert_failure_graph_is_redacted(error, marker)


def test_inventory_readonly_policy_exposes_exact_scopes_and_operations() -> None:
    profile = resolve(GoogleOAuthOperationV1.PROJECTS_SEARCH)

    assert tuple(profile_id.value for profile_id in GoogleOAuthProfileIdV1) == (
        "inventory_readonly",
    )
    assert tuple(operation.value for operation in GoogleOAuthOperationV1) == (
        "projects.search",
        "keys.lookupKey",
        "projects.get",
        "keys.get",
        "keys.list",
        "projects.getBillingInfo",
    )
    assert type(profile) is GoogleOAuthAuthorizationProfileV1
    assert profile.profile_id is READONLY_PROFILE
    assert tuple(scope for scope in profile.minimal_scopes) == EXPECTED_SCOPES
    assert len(profile.minimal_scopes) == 4
    assert set(profile.minimal_scopes) == set(EXPECTED_SCOPES)
    assert len(set(profile.minimal_scopes)) == 4
    assert tuple(operation.value for operation in profile.allowed_operations) == (
        EXPECTED_OPERATIONS
    )
    assert profile.scope_fingerprint == EXPECTED_SCOPE_FINGERPRINT


@pytest.mark.parametrize(
    "operation",
    (
        GoogleOAuthOperationV1.PROJECTS_SEARCH,
        GoogleOAuthOperationV1.KEYS_LOOKUP_KEY,
        GoogleOAuthOperationV1.PROJECTS_GET,
        GoogleOAuthOperationV1.KEYS_GET,
        GoogleOAuthOperationV1.KEYS_LIST,
        GoogleOAuthOperationV1.PROJECTS_GET_BILLING_INFO,
    ),
)
def test_each_inventory_read_operation_resolves(
    operation: GoogleOAuthOperationV1,
) -> None:
    profile = resolve(operation)

    assert operation in profile.allowed_operations
    assert profile.profile_id is READONLY_PROFILE


def test_billing_read_is_allowed() -> None:
    profile = resolve(GoogleOAuthOperationV1.PROJECTS_GET_BILLING_INFO)

    assert (
        GoogleOAuthOperationV1.PROJECTS_GET_BILLING_INFO in profile.allowed_operations
    )


@pytest.mark.parametrize(
    "forbidden_operation",
    (
        "billing.resourceAssociations.create",
        "billing.resourceAssociations.delete",
        "resourcemanager.projects.createBillingAssignment",
        "resourcemanager.projects.deleteBillingAssignment",
        "billing.budgets.create",
        "billing.budgets.update",
        "billing.spendCaps.create",
        "resourcemanager.projects.delete",
        "resourcemanager.projects.undelete",
    ),
)
def test_billing_writes_and_project_lifecycle_are_forbidden(
    forbidden_operation: str,
) -> None:
    with pytest.raises(
        GoogleOAuthAuthorizationError,
        match="credential.oauth_operation_forbidden",
    ) as caught:
        resolve_google_oauth_profile_v1(READONLY_PROFILE, forbidden_operation)

    assert caught.value.code == "credential.oauth_operation_forbidden"


def test_unknown_profile_is_rejected_without_identifier_in_error() -> None:
    marker = "account-project-billing-key-token-secret"

    with pytest.raises(
        GoogleOAuthAuthorizationError,
        match="credential.oauth_profile_unknown",
    ) as caught:
        resolve_google_oauth_profile_v1(marker, GoogleOAuthOperationV1.PROJECTS_SEARCH)

    assert str(caught.value) == "credential.oauth_profile_unknown"
    assert marker not in repr(caught.value)
    assert marker not in str(caught.value)
    assert marker not in repr(caught.value.args)


@pytest.mark.parametrize(
    "invalid_value",
    (
        True,
        False,
        1,
        1.0,
        None,
        [],
        {},
        StringSubclass("inventory_readonly"),
        ExplodingComparison(),
    ),
)
def test_profile_type_boundary_rejects_non_exact_values_before_comparison(
    invalid_value: object,
) -> None:
    with pytest.raises(
        GoogleOAuthAuthorizationError,
        match="credential.oauth_request_invalid",
    ):
        resolve_google_oauth_profile_v1(
            invalid_value, GoogleOAuthOperationV1.PROJECTS_SEARCH
        )


@pytest.mark.parametrize(
    "invalid_value",
    (
        True,
        False,
        1,
        1.0,
        None,
        [],
        {},
        StringSubclass("projects.search"),
        ExplodingComparison(),
    ),
)
def test_operation_type_boundary_rejects_non_exact_values_before_comparison(
    invalid_value: object,
) -> None:
    with pytest.raises(
        GoogleOAuthAuthorizationError,
        match="credential.oauth_request_invalid",
    ):
        resolve_google_oauth_profile_v1(READONLY_PROFILE, invalid_value)


def test_type_validation_precedes_profile_and_operation_lookup() -> None:
    with pytest.raises(
        GoogleOAuthAuthorizationError,
        match="credential.oauth_request_invalid",
    ):
        resolve_google_oauth_profile_v1("future-profile", ExplodingComparison())


def test_exact_strings_are_closed_world_inputs_without_scope_expansion() -> None:
    profile = resolve_google_oauth_profile_v1("inventory_readonly", "projects.search")

    assert profile.minimal_scopes == EXPECTED_SCOPES
    with pytest.raises(TypeError):
        resolve_google_oauth_profile_v1(
            "inventory_readonly",
            "projects.search",
            scopes=("cloud-platform",),
        )


def test_policy_profile_is_immutable_and_not_publicly_constructible() -> None:
    profile = resolve(GoogleOAuthOperationV1.PROJECTS_SEARCH)

    assert is_dataclass(profile)
    with pytest.raises(FrozenInstanceError):
        profile.minimal_scopes = ("cloud-platform",)  # type: ignore[misc]
    with pytest.raises(TypeError):
        profile.allowed_operations[0] = GoogleOAuthOperationV1.PROJECTS_SEARCH  # type: ignore[index]
    with pytest.raises(TypeError):
        GoogleOAuthAuthorizationProfileV1()


def test_policy_resolution_is_deterministic_and_serializable_without_secrets() -> None:
    first = resolve(GoogleOAuthOperationV1.PROJECTS_SEARCH)
    second = resolve(GoogleOAuthOperationV1.PROJECTS_SEARCH)

    assert first is second
    assert first == second
    assert repr(first) == repr(second)
    assert str(first) == repr(first)
    assert asdict(first) == asdict(second)
    assert pickle.loads(pickle.dumps(first)) is first


def test_public_renderings_and_errors_are_token_and_identifier_free() -> None:
    profile = resolve(GoogleOAuthOperationV1.PROJECTS_GET_BILLING_INFO)
    forbidden = "resourcemanager.projects.delete"
    with pytest.raises(GoogleOAuthAuthorizationError) as caught:
        resolve_google_oauth_profile_v1(READONLY_PROFILE, forbidden)

    rendered = (
        repr(profile),
        str(profile),
        repr(asdict(profile)),
        pickle.dumps(profile).decode("latin1"),
        repr(caught.value),
        str(caught.value),
        repr(caught.value.args),
    )
    forbidden_markers = (
        "access_token",
        "refresh_token",
        "client_secret",
        "account_id",
        "project_id",
        "billing_account_id",
        "key_id",
        "/home/",
    )
    for value in rendered:
        assert all(marker not in value for marker in forbidden_markers)


def test_resolution_has_no_filesystem_environment_clock_network_or_browser_side_effect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail(*args: object, **kwargs: object) -> object:
        raise AssertionError("policy resolution must be side-effect free")

    before_environment = dict(os.environ)
    monkeypatch.setattr(builtins, "open", fail)
    monkeypatch.setattr(Path, "read_text", fail)
    monkeypatch.setattr(os, "getenv", fail)
    monkeypatch.setattr(time, "time", fail)
    monkeypatch.setattr(socket, "socket", fail)
    monkeypatch.setattr(webbrowser, "open", fail)

    profile = resolve(GoogleOAuthOperationV1.PROJECTS_GET_BILLING_INFO)

    assert profile.scope_fingerprint == EXPECTED_SCOPE_FINGERPRINT
    assert dict(os.environ) == before_environment
