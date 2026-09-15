from __future__ import annotations

import copy
from hashlib import sha256
import inspect
import json
import pickle
from types import MappingProxyType

import pytest

import the_hive.google_inventory_readonly_scan as scan
from the_hive import google_account_inventory as inventory
from the_hive import google_oauth_authorization as authorization


@pytest.mark.parametrize(
    ("operation", "project_number", "url"),
    (
        (
            authorization.GoogleOAuthOperationV1.PROJECTS_SEARCH,
            None,
            "https://cloudresourcemanager.googleapis.com/v3/projects:search",
        ),
        (
            authorization.GoogleOAuthOperationV1.BILLING_ACCOUNTS_LIST,
            None,
            "https://cloudbilling.googleapis.com/v1/billingAccounts",
        ),
        (
            authorization.GoogleOAuthOperationV1.SERVICES_LIST,
            "123456",
            "https://serviceusage.googleapis.com/v1/projects/123456/services?filter=state%3AENABLED",
        ),
        (
            authorization.GoogleOAuthOperationV1.KEYS_LIST,
            "123456",
            "https://apikeys.googleapis.com/v2/projects/123456/locations/global/keys",
        ),
    ),
)
def test_fixed_discovery_request_has_only_four_bodyless_get_templates(
    operation: object, project_number: object, url: str
) -> None:
    request = scan._fixed_discovery_page_request(
        operation, project_number=project_number, page_token=None
    )
    assert dict(request) == {"method": "GET", "url": url, "body": None}
    paged = scan._fixed_discovery_page_request(
        operation, project_number=project_number, page_token="synthetic+/=&?cursor"
    )
    separator = "&" if "?" in url else "?"
    assert paged["url"] == url + separator + "pageToken=synthetic%2B%2F%3D%26%3Fcursor"
    with pytest.raises(TypeError):
        request["method"] = "POST"
    assert tuple(inspect.signature(scan._fixed_discovery_page_request).parameters) == (
        "operation",
        "project_number",
        "page_token",
    )


@pytest.mark.parametrize(
    ("operation", "project_number", "page_token"),
    (
        ("projects.search", None, None),
        (authorization.GoogleOAuthOperationV1.KEYS_GET, "123", None),
        ("keys.getKeyString", "123", None),
        (authorization.GoogleOAuthOperationV1.PROJECTS_SEARCH, "123", None),
        (authorization.GoogleOAuthOperationV1.KEYS_LIST, None, None),
        (authorization.GoogleOAuthOperationV1.KEYS_LIST, "123/../operations", None),
        (authorization.GoogleOAuthOperationV1.SERVICES_LIST, "0123", None),
        (authorization.GoogleOAuthOperationV1.PROJECTS_SEARCH, None, ""),
        (authorization.GoogleOAuthOperationV1.PROJECTS_SEARCH, None, "\x00"),
        (authorization.GoogleOAuthOperationV1.PROJECTS_SEARCH, None, "x" * 4097),
    ),
)
def test_fixed_discovery_request_rejects_nonclosed_operations_and_resource_paths(
    operation: object, project_number: object, page_token: object
) -> None:
    with pytest.raises(scan.GoogleInventoryReadonlyScanError) as caught:
        scan._fixed_discovery_page_request(
            operation, project_number=project_number, page_token=page_token
        )
    assert caught.value.code == "inventory.readonly_scan_discovery_invalid"


@pytest.mark.parametrize(
    ("operation", "collection", "row", "expected"),
    (
        (
            authorization.GoogleOAuthOperationV1.PROJECTS_SEARCH,
            "projects",
            {
                "name": "projects/123",
                "projectId": "synthetic-project",
                "state": "ACTIVE",
                "displayName": "Synthetic",
            },
            {
                "project_id": "synthetic-project",
                "project_number": "123",
                "state": "ACTIVE",
                "project_name": "Synthetic",
            },
        ),
        (
            authorization.GoogleOAuthOperationV1.BILLING_ACCOUNTS_LIST,
            "billingAccounts",
            {
                "name": "billingAccounts/ABCDEF-123456-ABCDEF",
                "displayName": "Synthetic Billing",
            },
            {
                "billing_account_id": "ABCDEF-123456-ABCDEF",
                "label": "Synthetic Billing",
            },
        ),
        (
            authorization.GoogleOAuthOperationV1.SERVICES_LIST,
            "services",
            {
                "name": "projects/123/services/synthetic.googleapis.com",
                "state": "ENABLED",
            },
            {"service_name": "projects/123/services/synthetic.googleapis.com"},
        ),
        (
            authorization.GoogleOAuthOperationV1.KEYS_LIST,
            "keys",
            {
                "name": "projects/123/locations/global/keys/synthetic-key",
                "uid": "synthetic-uid",
                "displayName": "Synthetic Key",
            },
            {
                "key_id": "projects/123/locations/global/keys/synthetic-key",
                "key_uid": "synthetic-uid",
                "key_name": "Synthetic Key",
            },
        ),
    ),
)
def test_fixed_discovery_page_projects_only_supported_metadata(
    operation: object,
    collection: str,
    row: dict[str, object],
    expected: dict[str, object],
) -> None:
    raw_row = dict(row, ignoredProviderField={"synthetic": "not persisted"})
    rows, cursor = scan._normalise_fixed_discovery_page(
        operation,
        {collection: [raw_row], "nextPageToken": "synthetic-cursor"},
        project_number="123" if collection in {"services", "keys"} else None,
    )
    assert rows == (expected,)
    assert cursor == "synthetic-cursor"
    assert "ignoredProviderField" not in repr(rows)


@pytest.mark.parametrize(
    "page",
    (
        {"keys": [{"name": "projects/999/locations/global/keys/synthetic-key"}]},
        {"keys": [{"name": "projects/123/locations/eu/keys/synthetic-key"}]},
        {"keys": [{"name": "projects/123/locations/global/keys/../getKeyString"}]},
        {
            "keys": [
                {
                    "name": "projects/123/locations/global/keys/synthetic-key",
                    "keyString": "synthetic-secret",
                }
            ]
        },
        {"keys": [], "nextPageToken": 1},
        {"keys": [], "error": "synthetic-provider-error"},
        {"keys": {}},
    ),
)
def test_fixed_discovery_page_rejects_wrong_parents_and_secret_responses(
    page: object,
) -> None:
    with pytest.raises(scan.GoogleInventoryReadonlyScanError) as caught:
        scan._normalise_fixed_discovery_page(
            authorization.GoogleOAuthOperationV1.KEYS_LIST, page, project_number="123"
        )
    assert str(caught.value) == "inventory.readonly_scan_discovery_invalid"
    assert "synthetic" not in repr(caught.value)


class _SyntheticPageLease:
    def __init__(self, pages: list[object]) -> None:
        self.pages = iter(pages)
        self.calls: list[tuple[object, object, object]] = []

    def _read_fixed_page(
        self, operation: object, *, project_number: object, page_token: object
    ) -> object:
        self.calls.append((operation, project_number, page_token))
        response = next(self.pages)
        if isinstance(response, Exception):
            raise response
        return response


def test_collect_fixed_discovery_pages_follows_only_server_cursor_and_stops() -> None:
    operation = authorization.GoogleOAuthOperationV1.BILLING_ACCOUNTS_LIST
    lease = _SyntheticPageLease(
        [
            {
                "billingAccounts": [{"name": "billingAccounts/SYNTHETIC-A"}],
                "nextPageToken": "synthetic-cursor",
            },
            {"billingAccounts": [{"name": "billingAccounts/SYNTHETIC-B"}]},
        ]
    )
    assert scan._collect_fixed_discovery_pages(lease, operation) == (
        {"billing_account_id": "SYNTHETIC-A", "label": None},
        {"billing_account_id": "SYNTHETIC-B", "label": None},
    )
    assert lease.calls == [
        (operation, None, None),
        (operation, None, "synthetic-cursor"),
    ]


@pytest.mark.parametrize(
    "pages",
    (
        [{"nextPageToken": "repeat"}, {"nextPageToken": "repeat"}],
        [
            {
                "billingAccounts": [{"name": "billingAccounts/SYNTHETIC"}],
                "nextPageToken": "next",
            },
            {"billingAccounts": [{"name": "billingAccounts/SYNTHETIC"}]},
        ],
        [RuntimeError("synthetic-provider-sensitive-detail")],
    ),
)
def test_collect_fixed_discovery_pages_rejects_cycles_duplicates_and_never_retries(
    pages: list[object],
) -> None:
    import traceback

    lease = _SyntheticPageLease(pages)
    with pytest.raises(scan.GoogleInventoryReadonlyScanError) as caught:
        scan._collect_fixed_discovery_pages(
            lease, authorization.GoogleOAuthOperationV1.BILLING_ACCOUNTS_LIST
        )
    assert len(lease.calls) == len(pages)
    assert "synthetic-provider-sensitive-detail" not in "".join(
        traceback.format_exception(caught.value)
    )


def test_collect_fixed_discovery_pages_bounds_pages_and_total_records(
    monkeypatch,
) -> None:
    monkeypatch.setattr(scan, "_MAX_DISCOVERY_PAGES", 2)
    lease = _SyntheticPageLease([{"nextPageToken": "one"}, {"nextPageToken": "two"}])
    with pytest.raises(scan.GoogleInventoryReadonlyScanError):
        scan._collect_fixed_discovery_pages(
            lease, authorization.GoogleOAuthOperationV1.BILLING_ACCOUNTS_LIST
        )
    assert len(lease.calls) == 2
    monkeypatch.setattr(scan, "_MAX_DISCOVERY_RECORDS", 1)
    lease = _SyntheticPageLease(
        [
            {
                "billingAccounts": [{"name": "billingAccounts/SYNTHETIC-A"}],
                "nextPageToken": "next",
            },
            {"billingAccounts": [{"name": "billingAccounts/SYNTHETIC-B"}]},
        ]
    )
    with pytest.raises(scan.GoogleInventoryReadonlyScanError):
        scan._collect_fixed_discovery_pages(
            lease, authorization.GoogleOAuthOperationV1.BILLING_ACCOUNTS_LIST
        )
    assert len(lease.calls) == 2


def _fingerprint(value: str) -> str:
    return "sha256:" + sha256(value.encode("utf-8")).hexdigest()


def test_scan_broker_has_no_public_constructor_or_caller_configuration_surface() -> (
    None
):
    """Catch a public broker that lets a caller install scan dependencies."""

    assert not hasattr(scan, "GoogleInventoryReadonlyScanBroker")


def _canonical_document() -> dict[str, object]:
    return {
        "schema_version": 3,
        "authority_generation": 7,
        "google_accounts": [
            {
                "ref": "synthetic-account-ref",
                "login_email": "synthetic-login@example.invalid",
                "recovery_email": None,
                "label": "synthetic-label",
                "subject_id": "synthetic-subject-ref",
                "auth": {
                    "access_token": "synthetic-access-placeholder",
                    "refresh_token": "synthetic-refresh-placeholder",
                    "client_fingerprint": "synthetic-client-placeholder",
                    "cookies": [],
                },
                "billing_accounts": [
                    {
                        "ref": "synthetic-billing-ref",
                        "billing_account_id": "synthetic-billing-identifier",
                        "label": "synthetic-billing-label",
                    }
                ],
                "projects": [
                    {
                        "ref": "the-hive-1",
                        "billing_account_ref": "synthetic-billing-ref",
                        "status": "active",
                        "project_id": "synthetic-project-identifier",
                        "project_number": "synthetic-project-number",
                        "key_id": "synthetic-key-identifier",
                        "key_uid": "synthetic-key-uid",
                        "project_name": "Synthetic Project",
                        "purpose": "external",
                        "key_name": "Synthetic Key",
                        "secret": None,
                    }
                ],
            }
        ],
    }


def _target_account() -> dict[str, object]:
    target = copy.deepcopy(_canonical_document()["google_accounts"][0])
    assert type(target) is dict
    target.pop("auth")
    projects = target["projects"]
    assert type(projects) is list
    assert type(projects[0]) is dict
    projects[0].pop("secret")
    projects[0]["status"] = "blocked"
    return target


def test_scan_test_document_normalises_durable_schema_generation_without_mutating() -> (
    None
):
    source = _canonical_document()
    copied = scan._document_for_validation(source)
    assert copied["schema_version"] == inventory._YamlIntegerLiteral("3")
    assert copied["authority_generation"] == inventory._YamlIntegerLiteral("7")
    assert source["schema_version"] == 3
    assert source["authority_generation"] == 7
    inventory._build_document(copied)


def test_fixed_discovery_target_updates_only_existing_identity_bound_slots() -> None:
    source = _target_account()
    source["projects"][0]["project_number"] = "123"
    source["projects"][0]["key_uid"] = "synthetic-uid"
    before = copy.deepcopy(source)
    target = scan._project_fixed_discovery_target(
        source,
        account_ref="synthetic-account-ref",
        subject_id="synthetic-subject-ref",
        projects=(
            {
                "project_id": "synthetic-project-identifier",
                "project_number": "123",
                "state": "ACTIVE",
                "project_name": "Updated Synthetic Project",
            },
            {
                "project_id": "synthetic-unbound-project",
                "project_number": "999",
                "state": "ACTIVE",
                "project_name": "Unbound",
            },
        ),
        billings=(
            {
                "billing_account_id": "synthetic-billing-identifier",
                "label": "Updated Synthetic Billing",
            },
        ),
        keys=(
            {
                "key_id": "projects/123/locations/global/keys/synthetic-key-identifier",
                "key_uid": "synthetic-uid",
                "key_name": "Updated Synthetic Key",
            },
        ),
    )
    assert source == before
    expected = copy.deepcopy(source)
    expected["projects"][0]["project_name"] = "Updated Synthetic Project"
    expected["projects"][0]["key_name"] = "Updated Synthetic Key"
    expected["billing_accounts"][0]["label"] = "Updated Synthetic Billing"
    assert target == expected
    assert len(target["projects"]) == 1
    assert target["projects"][0]["status"] == "blocked"
    assert target["projects"][0]["billing_account_ref"] == "synthetic-billing-ref"


def test_fixed_discovery_target_rejects_existing_project_or_key_identity_conflict() -> (
    None
):
    source = _target_account()
    source["projects"][0]["project_number"] = "123"
    project = {
        "project_id": "synthetic-project-identifier",
        "project_number": "999",
        "state": "ACTIVE",
        "project_name": None,
    }
    with pytest.raises(scan.GoogleInventoryReadonlyScanError):
        scan._project_fixed_discovery_target(
            source,
            account_ref="synthetic-account-ref",
            subject_id="synthetic-subject-ref",
            projects=(project,),
            billings=(),
            keys=(),
        )
    project["project_number"] = "123"
    with pytest.raises(scan.GoogleInventoryReadonlyScanError):
        scan._project_fixed_discovery_target(
            source,
            account_ref="synthetic-account-ref",
            subject_id="synthetic-subject-ref",
            projects=(project,),
            billings=(),
            keys=(
                {
                    "key_id": "projects/123/locations/global/keys/synthetic-key-identifier",
                    "key_uid": "different-synthetic-uid",
                    "key_name": None,
                },
            ),
        )


def test_scan_rejects_a_stale_or_mismatched_binding_before_broker_or_discovery() -> (
    None
):
    """Catch a scan that reaches a capability or discovery after binding drift."""

    document = _canonical_document()
    parsed = inventory._build_document(scan._document_for_validation(document))
    broker = _BrokerPort()
    discovery = _DiscoveryPort(_target_account())
    component, owner = scan._for_test_scan_component(
        broker=broker,
        discovery=discovery,
        clock=lambda: 100.0,
        plan_id_factory=lambda: "opaque-plan-id",
    )
    binding = component._new_verified_binding_for_control(
        owner,
        account_ref="synthetic-account-ref",
        subject_id="synthetic-subject-ref",
        inventory_generation=7,
        content_fingerprint=parsed.content_fingerprint,
        oauth_client_fingerprint=_fingerprint("synthetic-client"),
        scope_fingerprint=_fingerprint("synthetic-scope"),
        receipt_operation_digest=_fingerprint("receipt-operation"),
        receipt_binding_fingerprint=_fingerprint("receipt-binding"),
    )
    changed = copy.deepcopy(document)
    changed_account = changed["google_accounts"][0]
    assert type(changed_account) is dict
    changed_account["subject_id"] = "synthetic-other-subject"

    with pytest.raises(scan.GoogleInventoryReadonlyScanError) as caught:
        component._scan_for_control(owner, binding, changed)

    assert caught.value.code == "inventory.readonly_scan_request_invalid"
    assert broker.capabilities == []
    assert discovery.calls == 0


def test_scan_binding_checks_durable_generation_even_when_content_is_identical() -> (
    None
):
    source = _canonical_document()
    fingerprint = inventory._build_document(
        scan._document_for_validation(source)
    ).content_fingerprint
    source["authority_generation"] = 8
    with pytest.raises(scan.GoogleInventoryReadonlyScanError) as caught:
        scan._verify_current_document_binding(
            source,
            account_ref="synthetic-account-ref",
            subject_id="synthetic-subject-ref",
            inventory_generation=7,
            content_fingerprint=fingerprint,
        )
    assert caught.value.code == "inventory.readonly_scan_request_invalid"


def test_scan_rejects_generation_only_drift_before_issuing_broker_capability() -> None:
    source = _canonical_document()
    source["authority_generation"] = 8
    broker = _BrokerPort()
    with pytest.raises(scan.GoogleInventoryReadonlyScanError) as caught:
        _scan(canonical_document=source, broker=broker)
    assert caught.value.code == "inventory.readonly_scan_request_invalid"
    assert broker.capabilities == []


class _BrokerPort:
    def __init__(self) -> None:
        self.capabilities: list[object] = []
        self.closed = 0
        self.reuse = False
        self.receipts = []

    def issue_scan_capability(
        self,
        *,
        account_ref: str,
        subject_id: str,
        inventory_generation: int,
        content_fingerprint: str,
        oauth_client_fingerprint: str,
        scope_fingerprint: str,
        receipt_operation_digest: str | None = None,
        receipt_binding_fingerprint: str | None = None,
    ) -> object:
        self.receipts.append((receipt_operation_digest, receipt_binding_fingerprint))
        if self.reuse:
            return self.capabilities[-1]
        capability = scan._issue_scan_capability_for_broker(
            self,
            account_ref=account_ref,
            subject_id=subject_id,
            inventory_generation=inventory_generation,
            content_fingerprint=content_fingerprint,
            oauth_client_fingerprint=oauth_client_fingerprint,
            scope_fingerprint=scope_fingerprint,
        )
        self.capabilities.append(capability)
        return capability

    def close_scan_capability(self, capability: object) -> None:
        assert capability is self.capabilities[-1]
        self.closed += 1


class _SyntheticLeaseBroker(_BrokerPort):
    def __init__(self, lease: object) -> None:
        super().__init__()
        self.lease = lease
        self.opens = 0

    def _open_readonly_discovery_lease(self, capability: object) -> object:
        assert capability._broker is self
        assert capability._consumed is True
        assert capability._discovery_claimed is True
        self.opens += 1
        if isinstance(self.lease, Exception):
            raise self.lease
        return self.lease


class _SyntheticFixedLease(_SyntheticPageLease):
    def __init__(self, pages: list[object], target: dict[str, object]) -> None:
        super().__init__(pages)
        self.target = target
        self.closed = 0

    def _target_account_for_discovery(self) -> object:
        return copy.deepcopy(self.target)

    def _close(self) -> None:
        self.closed += 1


def test_fixed_discovery_leaf_constructor_accepts_only_private_broker_contract() -> (
    None
):
    broker = _SyntheticLeaseBroker(None)
    leaf = scan._FixedGoogleInventoryReadonlyDiscoveryV1(broker)
    assert leaf._broker is broker
    assert tuple(inspect.signature(type(leaf)).parameters) == ("broker",)
    with pytest.raises(scan.GoogleInventoryReadonlyScanError) as caught:
        scan._FixedGoogleInventoryReadonlyDiscoveryV1(object())
    assert caught.value.code == "inventory.readonly_scan_unavailable"


def test_fixed_discovery_leaf_repr_is_redacted_and_surface_is_closed() -> None:
    leaf = scan._FixedGoogleInventoryReadonlyDiscoveryV1(_SyntheticLeaseBroker(None))
    assert repr(leaf) == "_FixedGoogleInventoryReadonlyDiscoveryV1(<redacted>)"
    assert str(leaf) == repr(leaf)
    assert not hasattr(leaf, "__dict__")
    public_methods = {
        name
        for name in dir(type(leaf))
        if not name.startswith("_") and callable(getattr(type(leaf), name))
    }
    assert public_methods == {"discover_readonly_inventory"}
    assert not hasattr(scan, "FixedGoogleInventoryReadonlyDiscoveryV1")


@pytest.mark.parametrize("serialize", (copy.copy, copy.deepcopy, pickle.dumps))
def test_fixed_discovery_leaf_cannot_be_copied_or_serialized(serialize) -> None:
    leaf = scan._FixedGoogleInventoryReadonlyDiscoveryV1(_SyntheticLeaseBroker(None))
    with pytest.raises(TypeError, match="not serializable"):
        serialize(leaf)


def _fixed_leaf_capability(broker: _SyntheticLeaseBroker) -> object:
    binding = {
        "account_ref": "synthetic-account-ref",
        "subject_id": "synthetic-subject-ref",
        "inventory_generation": 7,
        "content_fingerprint": _fingerprint("source"),
        "oauth_client_fingerprint": _fingerprint("client"),
        "scope_fingerprint": _fingerprint("scope"),
    }
    capability = broker.issue_scan_capability(**binding)
    capability._consume_for_discovery(broker, **binding)
    return capability


def test_fixed_discovery_leaf_runs_all_four_templates_with_paging_into_sealed_plan() -> (
    None
):
    document = _canonical_document()
    document["google_accounts"][0]["projects"][0]["project_number"] = "123"
    target = _target_account()
    target["projects"][0]["project_number"] = "123"
    lease = _SyntheticFixedLease(
        [
            {
                "projects": [
                    {
                        "name": "projects/123",
                        "projectId": "synthetic-project-identifier",
                        "state": "ACTIVE",
                        "displayName": "Updated Project",
                    }
                ],
                "nextPageToken": "projects-next",
            },
            {
                "projects": [
                    {
                        "name": "projects/456",
                        "projectId": "synthetic-other-project",
                        "state": "ACTIVE",
                    }
                ]
            },
            {
                "billingAccounts": [
                    {
                        "name": "billingAccounts/synthetic-billing-identifier",
                        "displayName": "Updated Billing",
                    }
                ],
                "nextPageToken": "synthetic-billing-next",
            },
            {"billingAccounts": [{"name": "billingAccounts/synthetic-other-billing"}]},
            {
                "services": [
                    {
                        "name": "projects/123/services/synthetic-a.googleapis.com",
                        "state": "ENABLED",
                    }
                ],
                "nextPageToken": "services-next",
            },
            {
                "services": [
                    {
                        "name": "projects/123/services/synthetic-b.googleapis.com",
                        "state": "ENABLED",
                    }
                ]
            },
            {
                "keys": [
                    {
                        "name": "projects/123/locations/global/keys/synthetic-key-identifier",
                        "uid": "synthetic-key-uid",
                        "displayName": "Updated Key",
                    }
                ],
                "nextPageToken": "keys-next",
            },
            {
                "keys": [
                    {"name": "projects/123/locations/global/keys/synthetic-other-key"}
                ]
            },
            {"services": []},
            {"keys": []},
        ],
        target,
    )
    broker = _SyntheticLeaseBroker(lease)
    leaf = scan._FixedGoogleInventoryReadonlyDiscoveryV1(broker)
    component, owner = scan._for_test_scan_component(
        broker=broker,
        discovery=leaf,
        clock=lambda: 100.0,
        plan_id_factory=lambda: "synthetic-plan",
    )
    binding = component._new_verified_binding_for_control(
        owner,
        account_ref="synthetic-account-ref",
        subject_id="synthetic-subject-ref",
        inventory_generation=7,
        content_fingerprint=inventory._build_document(
            scan._document_for_validation(document)
        ).content_fingerprint,
        oauth_client_fingerprint=_fingerprint("client"),
        scope_fingerprint=_fingerprint("scope"),
        receipt_operation_digest=_fingerprint("receipt-operation"),
        receipt_binding_fingerprint=_fingerprint("receipt-binding"),
    )
    result = component._scan_for_control(owner, binding, document)
    operations = authorization.GoogleOAuthOperationV1
    assert lease.calls == [
        (operations.PROJECTS_SEARCH, None, None),
        (operations.PROJECTS_SEARCH, None, "projects-next"),
        (operations.BILLING_ACCOUNTS_LIST, None, None),
        (operations.BILLING_ACCOUNTS_LIST, None, "synthetic-billing-next"),
        (operations.SERVICES_LIST, "123", None),
        (operations.SERVICES_LIST, "123", "services-next"),
        (operations.KEYS_LIST, "123", None),
        (operations.KEYS_LIST, "123", "keys-next"),
        (operations.SERVICES_LIST, "456", None),
        (operations.KEYS_LIST, "456", None),
    ]
    assert broker.opens == broker.closed == lease.closed == 1
    assert result._public_projection["project_count"] == 2
    assert result._public_projection["billing_account_count"] == 2
    assert result._public_projection["service_count"] == 2
    assert result._public_projection["key_count"] == 2
    sealed = result._plan._export_sealed_for_authority()
    assert b"Updated Project" in sealed
    assert b"Updated Billing" in sealed
    assert b"Updated Key" in sealed
    for marker in (
        b"synthetic-access-placeholder",
        b"synthetic-refresh-placeholder",
        b"projects-next",
    ):
        assert marker not in sealed
    assert "synthetic" not in repr(result._public_projection)
    with pytest.raises(scan.GoogleInventoryReadonlyScanError):
        leaf.discover_readonly_inventory(broker.capabilities[0])
    assert broker.opens == 1


@pytest.mark.parametrize("failure_stage", ("open", "target", "page", "close"))
def test_fixed_discovery_leaf_redacts_failures_and_closes_lease_once(
    failure_stage,
) -> None:
    import traceback

    target = _target_account()
    pages = [{}, {}]
    if failure_stage == "target":
        target["subject_id"] = "synthetic-wrong-subject"
    if failure_stage == "page":
        pages = [RuntimeError("synthetic-sensitive-provider-error")]
    lease = _SyntheticFixedLease(pages, target)
    if failure_stage == "close":

        def failing_close():
            lease.closed += 1
            raise RuntimeError("synthetic-sensitive-cleanup-error")

        lease._close = failing_close
    broker = _SyntheticLeaseBroker(
        RuntimeError("synthetic-sensitive-open-error")
        if failure_stage == "open"
        else lease
    )
    leaf = scan._FixedGoogleInventoryReadonlyDiscoveryV1(broker)
    capability = _fixed_leaf_capability(broker)
    with pytest.raises(scan.GoogleInventoryReadonlyScanError) as caught:
        leaf.discover_readonly_inventory(capability)
    assert "synthetic-sensitive" not in "".join(
        traceback.format_exception(caught.value)
    )
    assert broker.opens == 1
    assert lease.closed == (0 if failure_stage == "open" else 1)
    with pytest.raises(scan.GoogleInventoryReadonlyScanError):
        leaf.discover_readonly_inventory(capability)
    assert broker.opens == 1


def test_fixed_discovery_leaf_rejects_unconsumed_or_wrong_capability_before_lease() -> (
    None
):
    broker = _SyntheticLeaseBroker(None)
    leaf = scan._FixedGoogleInventoryReadonlyDiscoveryV1(broker)
    capability = _fixed_leaf_capability(broker)
    capability._consumed = False
    for invalid in (
        object(),
        capability,
        _fixed_leaf_capability(_SyntheticLeaseBroker(None)),
    ):
        with pytest.raises(scan.GoogleInventoryReadonlyScanError):
            leaf.discover_readonly_inventory(invalid)
    assert broker.opens == 0


class _DiscoveryPort:
    def __init__(self, target: dict[str, object], *, reverse: bool = False) -> None:
        self._target = target
        self._reverse = reverse
        self.calls = 0

    def discover_readonly_inventory(self, capability: object) -> object:
        self.calls += 1
        assert type(capability) is scan._GoogleInventoryReadonlyScanCapabilityV1
        projects = (
            {"project_id": "synthetic-project-identifier-b", "state": "ACTIVE"},
            {"project_id": "synthetic-project-identifier-a", "state": "ACTIVE"},
        )
        billings = ({"billing_account_id": "synthetic-billing-identifier"},)
        services = ({"service_name": "synthetic-service-name"},)
        keys = ({"key_id": "synthetic-key-identifier"},)
        if self._reverse:
            projects = tuple(reversed(projects))
        return scan._GoogleInventoryReadonlyDiscoveryResultV1._issue_for_port(
            self,
            projects=projects,
            billings=billings,
            services=services,
            keys=keys,
            canonical_target_account=self._target,
        )


def _scan(
    *,
    target: dict[str, object] | None = None,
    canonical_document: dict[str, object] | None = None,
    reverse: bool = False,
    broker: _BrokerPort | None = None,
) -> tuple[scan._GoogleInventoryReadonlyScanResultV1, _BrokerPort]:
    actual_broker = broker if broker is not None else _BrokerPort()
    document = (
        _canonical_document() if canonical_document is None else canonical_document
    )
    source_fingerprint = inventory._build_document(
        scan._document_for_validation(document)
    ).content_fingerprint
    component, owner = scan._for_test_scan_component(
        broker=actual_broker,
        discovery=_DiscoveryPort(target or _target_account(), reverse=reverse),
        clock=lambda: 100.0,
        plan_id_factory=lambda: "opaque-plan-id",
    )
    binding = component._new_verified_binding_for_control(
        owner,
        account_ref="synthetic-account-ref",
        subject_id="synthetic-subject-ref",
        inventory_generation=7,
        content_fingerprint=source_fingerprint,
        oauth_client_fingerprint=_fingerprint("client"),
        scope_fingerprint=_fingerprint("scope"),
        receipt_operation_digest=_fingerprint("receipt-operation"),
        receipt_binding_fingerprint=_fingerprint("receipt-binding"),
    )
    result = component._scan_for_control(
        owner,
        binding,
        document,
    )
    return result, actual_broker


def test_receipt_binding_crosses_only_the_private_broker_boundary() -> None:
    result, broker = _scan()
    expected = (_fingerprint("receipt-operation"), _fingerprint("receipt-binding"))
    assert broker.receipts == [expected]
    exposed = (
        repr(result)
        + repr(result._plan._binding_for_authority())
        + result._plan._export_sealed_for_authority().decode()
    )
    assert all(value not in exposed for value in expected)


def test_plan_store_transform_returns_plain_durable_integers_without_advancing_generation():
    result, _broker = _scan()
    document = _canonical_document()
    result._plan._transform_for_authority(document)
    assert type(document["schema_version"]) is int
    assert document["schema_version"] == 3
    assert type(document["authority_generation"]) is int
    assert document["authority_generation"] == 7


@pytest.mark.parametrize(
    "field,value",
    [
        ("receipt_operation_digest", None),
        ("receipt_binding_fingerprint", "invalid"),
        ("receipt_operation_digest", object()),
    ],
)
def test_verified_binding_rejects_unvalidated_receipt_fields(field, value) -> None:
    component, owner = scan._for_test_scan_component(
        broker=_BrokerPort(),
        discovery=_DiscoveryPort(_target_account()),
        clock=lambda: 100.0,
        plan_id_factory=lambda: "opaque-plan-id",
    )
    fields = dict(
        account_ref="synthetic-account-ref",
        subject_id="synthetic-subject-ref",
        inventory_generation=7,
        content_fingerprint=_fingerprint("content"),
        oauth_client_fingerprint=_fingerprint("client"),
        scope_fingerprint=_fingerprint("scope"),
        receipt_operation_digest=_fingerprint("receipt-operation"),
        receipt_binding_fingerprint=_fingerprint("receipt-binding"),
    )
    fields[field] = value
    with pytest.raises(scan.GoogleInventoryReadonlyScanError):
        component._new_verified_binding_for_control(owner, **fields)


def test_scan_capability_is_one_use_redacted_and_not_copyable_or_serializable() -> None:
    result, broker = _scan()

    capability = broker.capabilities[0]
    assert broker.closed == 1
    assert "synthetic-access-placeholder" not in repr(capability)
    assert "synthetic-refresh-placeholder" not in repr(capability)
    with pytest.raises(TypeError, match="not serializable"):
        copy.copy(capability)
    with pytest.raises(TypeError, match="not serializable"):
        copy.deepcopy(capability)
    with pytest.raises(TypeError, match="not serializable"):
        pickle.dumps(capability)

    broker.reuse = True
    with pytest.raises(scan.GoogleInventoryReadonlyScanError) as caught:
        _scan(broker=broker)
    assert caught.value.code == "inventory.readonly_scan_capability_invalid"
    assert type(result._plan) is scan._GoogleInventoryReadonlyPlanV1


def test_fixed_discovery_capability_starts_with_a_fresh_atomic_claim() -> None:
    _, broker = _scan()
    capability = broker.capabilities[0]
    assert capability._discovery_claimed is False
    assert capability._discovery_lock.acquire(blocking=False)
    capability._discovery_lock.release()


def test_fixed_discovery_capability_claim_rejects_wrong_owner_and_concurrent_reuse() -> (
    None
):
    from concurrent.futures import ThreadPoolExecutor

    _, broker = _scan()
    capability = broker.capabilities[0]
    with pytest.raises(scan.GoogleInventoryReadonlyScanError):
        capability._claim_for_fixed_discovery(object())

    def claim() -> str:
        try:
            capability._claim_for_fixed_discovery(broker)
        except scan.GoogleInventoryReadonlyScanError as error:
            return error.code
        return "claimed"

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: claim(), range(2)))
    assert sorted(results) == ["claimed", "inventory.readonly_scan_capability_invalid"]


def test_discovery_port_has_no_free_url_method_or_body_and_plan_is_canonically_bound() -> (
    None
):
    first, _ = _scan(reverse=False)
    second, _ = _scan(reverse=True)

    signature = inspect.signature(
        scan._GoogleInventoryReadonlyDiscoveryPortV1.discover_readonly_inventory
    )
    assert tuple(signature.parameters) == ("self", "capability")
    first_binding = first._plan._binding_for_authority()
    second_binding = second._plan._binding_for_authority()
    assert first_binding["plan_digest"] == second_binding["plan_digest"]
    assert first_binding["created_at"] == 100.0
    assert first_binding["expires_at"] > first_binding["created_at"]
    assert first._public_projection == MappingProxyType(
        {
            "status": "planned",
            "account_count": 1,
            "project_count": 2,
            "billing_account_count": 1,
            "service_count": 1,
            "key_count": 1,
            "changes": {"canonical_account": 1},
        }
    )


def test_plan_binding_is_immutable_and_public_projection_is_strictly_redacted() -> None:
    result, _ = _scan()
    plan = result._plan
    binding = plan._binding_for_authority()

    assert set(binding) == {
        "account_ref",
        "subject_id",
        "inventory_generation",
        "content_fingerprint",
        "oauth_client_fingerprint",
        "scope_fingerprint",
        "plan_id",
        "plan_digest",
        "resulting_content_fingerprint",
        "created_at",
        "expires_at",
    }
    assert binding["account_ref"] == "synthetic-account-ref"
    assert binding["subject_id"] == "synthetic-subject-ref"
    assert binding["inventory_generation"] == 7
    assert binding["plan_id"] == "opaque-plan-id"
    assert all(
        type(binding[field]) is str and str(binding[field]).startswith("sha256:")
        for field in (
            "content_fingerprint",
            "oauth_client_fingerprint",
            "scope_fingerprint",
            "plan_digest",
            "resulting_content_fingerprint",
        )
    )
    with pytest.raises(TypeError):
        binding["account_ref"] = "other"  # type: ignore[index]
    with pytest.raises(TypeError, match="not serializable"):
        pickle.dumps(plan)

    rendered_public = repr(result._public_projection)
    for marker in (
        "synthetic-login@example.invalid",
        "synthetic-subject-ref",
        "synthetic-project-identifier",
        "synthetic-billing-identifier",
        "synthetic-key-identifier",
        "synthetic-access-placeholder",
        "synthetic-refresh-placeholder",
    ):
        assert marker not in rendered_public


def test_plan_rechecks_its_sealed_private_bytes_before_authority_apply() -> None:
    result, _ = _scan()
    plan = result._plan

    assert plan._verify_for_authority() == plan._binding_for_authority()
    object.__setattr__(plan, "_sealed_payload", b"{}")
    with pytest.raises(scan.GoogleInventoryReadonlyScanError) as caught:
        plan._verify_for_authority()
    assert caught.value.code == "inventory.readonly_scan_plan_invalid"


def test_authority_can_rehydrate_only_the_verified_secret_free_plan_bytes() -> None:
    """Catch a durable-plan export that serializes auth or cannot be rechecked."""

    discovered_target = _target_account()
    target_projects = discovered_target["projects"]
    assert type(target_projects) is list and type(target_projects[0]) is dict
    target_projects[0]["purpose"] = "hive"
    target_projects[0]["status"] = "active"
    document = _canonical_document()
    source_account = document["google_accounts"][0]
    assert type(source_account) is dict
    current_auth = copy.deepcopy(source_account["auth"])
    source_projects = source_account["projects"]
    assert type(source_projects) is list and type(source_projects[0]) is dict
    source_projects[0]["purpose"] = "hive"
    source_projects[0]["status"] = "active"
    current_secret = "synthetic-canonical-placeholder"
    source_projects[0]["secret"] = current_secret
    result, _ = _scan(
        target=discovered_target,
        canonical_document=document,
    )
    sealed = result._plan._export_sealed_for_authority()

    assert sealed == result._plan._sealed_payload
    assert b'"auth"' not in sealed
    assert b'"secret"' not in sealed
    rehydrated = scan._rehydrate_sealed_plan_for_authority(sealed)
    assert rehydrated._binding_for_authority() == result._plan._binding_for_authority()
    assert current_secret.encode("utf-8") not in sealed
    rehydrated._transform_for_authority(document)
    target = document["google_accounts"][0]
    assert type(target) is dict
    assert target["auth"] == current_auth
    projects = target["projects"]
    assert type(projects) is list and type(projects[0]) is dict
    assert projects[0]["secret"] == current_secret


@pytest.mark.parametrize(
    "sealed",
    (
        b"not-json",
        b'{"binding":{}}',
        b'{"binding":{},"discovery_fingerprint":"not-a-fingerprint","target_account":{}}',
    ),
)
def test_rehydrate_sealed_plan_rejects_malformed_or_unknown_bytes(
    sealed: bytes,
) -> None:
    """Catch a recovery parser accepting an unbounded or non-schema plan."""

    with pytest.raises(scan.GoogleInventoryReadonlyScanError) as caught:
        scan._rehydrate_sealed_plan_for_authority(sealed)
    assert caught.value.code == "inventory.readonly_scan_plan_invalid"


def test_rehydrate_sealed_plan_rejects_binding_target_mismatch_and_tampering() -> None:
    """Catch recovery accepting a valsynthetic-id-looking plan whose binding was changed."""

    result, _ = _scan()
    payload = json.loads(result._plan._export_sealed_for_authority().decode("utf-8"))
    assert type(payload) is dict
    payload["unknown_field"] = None
    unknown = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    with pytest.raises(scan.GoogleInventoryReadonlyScanError) as caught:
        scan._rehydrate_sealed_plan_for_authority(unknown)
    assert caught.value.code == "inventory.readonly_scan_plan_invalid"
    payload.pop("unknown_field")
    binding = payload["binding"]
    assert type(binding) is dict
    binding["account_ref"] = "other-account"
    altered = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")

    with pytest.raises(scan.GoogleInventoryReadonlyScanError) as caught:
        scan._rehydrate_sealed_plan_for_authority(altered)
    assert caught.value.code == "inventory.readonly_scan_plan_invalid"
    with pytest.raises(scan.GoogleInventoryReadonlyScanError) as caught:
        scan._rehydrate_sealed_plan_for_authority(
            result._plan._export_sealed_for_authority() + b"\n"
        )
    assert caught.value.code == "inventory.readonly_scan_plan_invalid"


def test_plan_transform_only_replaces_the_validated_target_account_and_preserves_secrets() -> (
    None
):
    result, _ = _scan()
    document = _canonical_document()

    result._plan._transform_for_authority(document)

    inventory._build_document(scan._document_for_validation(document))
    target = document["google_accounts"][0]
    assert type(target) is dict
    assert target["auth"] == {
        "access_token": "synthetic-access-placeholder",
        "refresh_token": "synthetic-refresh-placeholder",
        "client_fingerprint": "synthetic-client-placeholder",
        "cookies": [],
    }
    projects = target["projects"]
    assert type(projects) is list and type(projects[0]) is dict
    assert projects[0]["status"] == "blocked"
    assert (
        result._plan._binding_for_authority()["resulting_content_fingerprint"]
        == inventory._build_document(
            scan._document_for_validation(document)
        ).content_fingerprint
    )


def test_unknown_canonical_update_shape_fails_closed_before_plan_issuance() -> None:
    target = _target_account()
    target["unsupported_discovery_field"] = "synthetic-provider-value"

    with pytest.raises(scan.GoogleInventoryReadonlyScanError) as caught:
        _scan(target=target)

    assert caught.value.code == "inventory.readonly_scan_plan_invalid"
