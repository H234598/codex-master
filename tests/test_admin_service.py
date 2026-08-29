from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from threading import Lock

import pytest
import codex_master.admin_service as admin_service_module

from codex_master.admin_contracts import AdminPrincipalV1, AdminRequestV1, OperationV1
from codex_master.admin_hosts import ControlHostV1
from codex_master.admin_operations import AdminOperationPlan, AdminOperationStore
from codex_master.google_account_inventory import GoogleAccountInventoryError
from codex_master.google_account_inventory_manager import (
    GoogleAccountInventoryStatusV1,
    InventoryManagerStateV1,
    InventorySourceTypeV1,
)
from codex_master.google_oauth_authorization import GoogleOAuthProfileIdV1
from codex_master.google_billing_service import (
    GoogleBillingError,
    GoogleBillingPlanV1,
    GoogleBillingReceiptV1,
)
from codex_master.google_cloud_provisioner import (
    FillToQuotaPlan,
    GoogleQuotaEvidenceV1,
    PlannedHiveProject,
    ProvisionReceipt,
)
from codex_master.google_oauth_session import (
    GoogleOAuthClientImportPlanV1,
    GoogleOAuthClientImportReceiptV1,
    GoogleOAuthSessionReceipt,
    GoogleOAuthTransactionV1,
)
from codex_master.openai_credential_service import AuthSyncPlanV1, AuthSyncReceiptV1
from codex_master.admin_service import (
    AdminDenied,
    AdminServiceError,
    MasterjetControlService,
    OpenAIAccountSummaryV1,
    SecretIngressSessionV1,
    SecretIngressUploadReceiptV1,
    SecretIngressCapabilityV1,
    SecretIngressResolutionV1,
)


DIGEST = "sha256:" + "a" * 64
CREATED = datetime(2026, 8, 28, 10, 0, tzinfo=UTC)


@dataclass(frozen=True)
class PublicValue:
    value: dict[str, object]

    def public_projection(self) -> dict[str, object]:
        return dict(self.value)


class OperationStore:
    def __init__(self) -> None:
        self.calls = 0
        self.kind = "google.provision:google-one"

    def get(self, operation_id: str) -> OperationV1:
        self.calls += 1
        return OperationV1(
            id=operation_id,
            kind=self.kind,
            state="planned",
            expected_generation=4,
            resulting_generation=None,
            plan_digest=DIGEST,
            created_at=CREATED,
            expires_at=CREATED + timedelta(minutes=15),
            completed_count=0,
            failed_count=0,
            not_attempted_count=1,
            reason_codes=("control.plan_ready",),
        )

    def plan(self, **values: object) -> AdminOperationPlan:
        operation = self.get("op-refresh")
        operation = OperationV1(
            operation.id,
            str(values["kind"]),
            "planned",
            int(values["generation"]),
            None,
            operation.plan_digest,
            operation.created_at,
            operation.expires_at,
            0,
            0,
            1,
            ("control.plan_ready",),
        )
        return AdminOperationPlan(
            operation.id,
            operation.plan_digest,
            operation.expected_generation,
            operation.created_at,
            operation.expires_at,
            operation,
        )

    def lookup_plan(self, **_values: object) -> AdminOperationPlan | None:
        return None

    def begin(self, operation_id: str, *, current_generation: int) -> OperationV1:
        return self.get(operation_id)

    def record_step(self, *_args: object, **_values: object) -> OperationV1:
        return self.get("op-refresh")

    def finish(
        self, operation_id: str, *, state: str, resulting_generation: int
    ) -> OperationV1:
        operation = self.get(operation_id)
        return OperationV1(
            operation.id,
            "google.inventory.refresh",
            state,
            4,
            resulting_generation,
            operation.plan_digest,
            operation.created_at,
            operation.expires_at,
            1,
            0,
            0,
            ("control.operation_succeeded",),
        )


class OpenAIAccounts:
    def __init__(self) -> None:
        self.calls = 0
        self.generation = 4

    def list_accounts(self) -> tuple[OpenAIAccountSummaryV1, ...]:
        self.calls += 1
        return (OpenAIAccountSummaryV1("openai-one", self.generation),)


class AccountRegistry:
    def __init__(self) -> None:
        self.generation = 4
        self.calls: list[tuple[object, ...]] = []

    def current_generation(self, provider: str) -> int:
        self.calls.append(("generation", provider))
        return self.generation

    def add_account(
        self,
        provider: str,
        account_ref: str,
        label: str,
        *,
        expected_generation: int,
        idempotency_key: str,
    ) -> dict[str, object]:
        self.calls.append(
            (
                "add",
                provider,
                account_ref,
                label,
                expected_generation,
                idempotency_key,
            )
        )
        self.generation += 1
        return {"account": {"ref": account_ref, "generation": self.generation}}

    def disable_account(
        self,
        provider: str,
        account_ref: str,
        *,
        expected_generation: int,
        idempotency_key: str,
    ) -> dict[str, object]:
        self.calls.append(
            ("disable", provider, account_ref, expected_generation, idempotency_key)
        )
        self.generation += 1
        return {"account": {"ref": account_ref, "generation": self.generation}}


class OpenAICredentials:
    def __init__(self) -> None:
        self.generation = 4
        self.plan_calls = 0
        self.apply_calls = 0
        self.last_plan: tuple[object, ...] | None = None
        self.resolve_error = False

    def account_generation(self, _account_ref: str) -> int:
        return self.generation

    def plan_auth_sync(
        self,
        account_ref: str,
        *,
        expected_generation: int,
        idempotency_key: str,
    ) -> AuthSyncPlanV1:
        self.plan_calls += 1
        self.last_plan = (account_ref, expected_generation, idempotency_key)
        return AuthSyncPlanV1(
            account_ref,
            expected_generation,
            1_000.0,
            "private-nonce",
            idempotency_key,
            "a" * 64,
            object(),
        )

    def apply_auth_sync(self, plan: object, upload: object) -> AuthSyncReceiptV1:
        self.apply_calls += 1
        assert plan == "openai-plan"
        assert upload == bytearray(b"openai-upload")
        return AuthSyncReceiptV1("openai-one", 5, "a" * 64)

    def resolve_auth_sync_plan(self, *_args: object, **_values: object) -> object:
        if self.resolve_error:
            raise RuntimeError("private-plan-error")
        return "openai-plan"

    def authorize_auth_ingress(self, _plan: object, upload: bytearray) -> bytearray:
        return upload

    def reconcile_auth_sync_plan(self, _plan: object) -> None:
        return None


class GoogleManager:
    def __init__(self) -> None:
        self.list_calls = 0
        self.project_calls = 0
        self.get_calls = 0
        self.reload_calls = 0
        self.generation = 4
        self._lock = Lock()

    def list_accounts(self) -> tuple[dict[str, object], ...]:
        with self._lock:
            self.list_calls += 1
        return (
            {
                "ref": "google-one",
                "label": "Google One",
                "subject_bound": True,
                "inventory_generation": self.generation,
                "project_count": 1,
                "billing_count": 1,
            },
        )

    def list_projects(self, account_ref: str) -> tuple[dict[str, object], ...]:
        self.project_calls += 1
        assert account_ref == "google-one"
        return (
            {
                "ref": "project-one",
                "project_name": "Quiet Project",
                "key_name": "Quiet Project Key",
                "purpose": "hive",
                "billing_ref": "billing-one",
                "status": "active",
                "inventory_generation": self.generation,
            },
        )

    def get_account(self, account_ref: str) -> dict[str, object]:
        self.get_calls += 1
        return {"ref": account_ref, "generation": 4}

    def inventory_generation(self) -> int:
        return self.generation

    def reload(self, *, expected_generation: int) -> GoogleAccountInventoryStatusV1:
        assert expected_generation == self.generation
        self.reload_calls += 1
        self.generation += 1
        return GoogleAccountInventoryStatusV1(
            InventoryManagerStateV1.READY,
            self.generation,
            "2026-08-28T10:00:00Z",
            InventorySourceTypeV1.TEST,
            "sha256:" + "b" * 64,
            True,
            None,
            1,
            1,
            1,
            1,
        )


class GoogleOAuth:
    def __init__(self) -> None:
        self.generation = 4
        self.calls: list[str] = []
        self.last_begin: tuple[str, dict[str, object]] | None = None
        self.bindings: dict[str, object] = {
            "google-one": admin_service_module.GoogleOAuthClientBindingV1(
                "google-one",
                4,
                "oauth-client-opaque",
                admin_service_module.GoogleOAuthClientAvailabilityV1.AVAILABLE,
            )
        }

    def account_generation(self, _account_ref: str) -> int:
        return self.generation

    def default_oauth_client_binding(
        self, account_ref: str, *, expected_generation: int
    ) -> object:
        return self.bindings.get(
            account_ref,
            admin_service_module.GoogleOAuthClientBindingV1(
                account_ref,
                expected_generation,
                None,
                admin_service_module.GoogleOAuthClientAvailabilityV1.MISSING,
            ),
        )

    def begin_oauth_transaction(
        self, account_ref: str, **values: object
    ) -> GoogleOAuthTransactionV1:
        self.calls.append("begin")
        self.last_begin = (account_ref, dict(values))
        return GoogleOAuthTransactionV1(
            "transaction-one",
            account_ref,
            "https://accounts.example/authorize?state=opaque",
            1_000.0,
            4,
        )

    def complete_oauth_transaction(
        self, transaction_id: str, **values: object
    ) -> GoogleOAuthSessionReceipt:
        self.calls.append("complete")
        assert values["code"] == "oauth-code"
        return GoogleOAuthSessionReceipt(str(values["account_ref"]), True, True)

    def plan_oauth_client_import(
        self, account_ref: str, **values: object
    ) -> GoogleOAuthClientImportPlanV1:
        self.calls.append("client-plan")
        return GoogleOAuthClientImportPlanV1(
            "oauth-import-one",
            account_ref,
            4,
            1_000.0,
            "request-one",
            "a" * 64,
        )

    def apply_oauth_client_import(
        self, plan: object, ingress_session: object
    ) -> GoogleOAuthClientImportReceiptV1:
        self.calls.append("client-apply")
        assert plan == "google-client-plan"
        assert type(ingress_session) is SecretIngressResolutionV1
        assert ingress_session.upload
        return GoogleOAuthClientImportReceiptV1(
            "google-one", "client-one", "Quiet Client", 4, "a" * 64
        )

    def resolve_oauth_client_import_plan(
        self, *_args: object, **_values: object
    ) -> object:
        return "google-client-plan"


class QuotaCollector:
    def __init__(self) -> None:
        self.calls = 0

    def collect(self, account_ref: str, *, expected_generation: int) -> PublicValue:
        self.calls += 1
        return PublicValue(
            {
                "account_ref": account_ref,
                "inventory_generation": expected_generation,
                "remaining": 3,
            }
        )


class GoogleProvisioner:
    def __init__(self) -> None:
        self.plan_calls = 0
        self.apply_calls = 0

    def plan(
        self,
        account_ref: str,
        *,
        expected_generation: int,
        idempotency_key: str,
        quota_evidence: object,
    ) -> FillToQuotaPlan:
        self.plan_calls += 1
        evidence = GoogleQuotaEvidenceV1(
            3,
            "2026-08-28T10:00:00Z",
            "admin",
            account_ref,
            expected_generation,
            "sha256:" + "b" * 64,
        )
        return FillToQuotaPlan(
            account_ref,
            "subject-one",
            3,
            evidence,
            expected_generation,
            "sha256:" + "b" * 64,
            (
                PlannedHiveProject(
                    "project-one",
                    "Quiet Project",
                    "quiet-project",
                    None,
                    "Quiet Project Key",
                ),
            ),
            "sha256:" + "a" * 64,
        )

    def apply(
        self,
        account_ref: str,
        *,
        expected_generation: int,
        idempotency_key: str,
        plan_digest: str,
    ) -> ProvisionReceipt:
        self.apply_calls += 1
        return ProvisionReceipt(1, 1)


class GoogleBilling:
    def __init__(self) -> None:
        self.plan_calls = 0
        self.apply_calls = 0
        self.last_plan: dict[str, object] | None = None
        self.last_apply: tuple[str, dict[str, object]] | None = None

    def plan_billing_binding(self, **values: object) -> GoogleBillingPlanV1:
        self.plan_calls += 1
        self.last_plan = dict(values)
        return GoogleBillingPlanV1(
            "billing-plan-one",
            "google-one",
            "subject-one",
            4,
            "sha256:" + "b" * 64,
            "project-one",
            "provider-project-one",
            "billing-one",
            "provider-billing-one",
            DIGEST,
            CREATED,
            CREATED + timedelta(minutes=5),
            "request-one",
        )

    def apply_billing_binding(
        self, plan_id: str, **values: object
    ) -> GoogleBillingReceiptV1:
        self.apply_calls += 1
        self.last_apply = (plan_id, dict(values))
        return GoogleBillingReceiptV1(
            plan_id, "succeeded", 1, 1, 0, 0, "billing.binding_created"
        )


class Hosts:
    def __init__(self) -> None:
        self.calls = 0

    def list(self) -> tuple[ControlHostV1, ...]:
        self.calls += 1
        return (
            ControlHostV1(
                "worker-one",
                "Worker One",
                "execution",
                {"kind": "ssh", "binding_ref": "worker-one"},
                ("codex.execute",),
                {"state": "reachable"},
                {"cpu_threads": 8, "memory_bytes": 16_000_000_000},
                4,
                CREATED,
                "host-agent",
            ),
        )


class SecretIngress:
    def __init__(self) -> None:
        self.create_calls = 0
        self.resolve_calls = 0
        self.put_calls = 0
        self.last_put: tuple[str, object, str] | None = None
        self.last_capability: object | None = None
        self.upload_claims: list[object] = []
        self.upload_commits = 0
        self.upload_rollbacks = 0
        self.resolve_commits = 0
        self.resolve_rollbacks = 0
        self.created_values: dict[str, object] | None = None
        self.last_resolution: SecretIngressResolutionV1 | None = None

    def create_session(self, **values: object) -> SecretIngressSessionV1:
        self.create_calls += 1
        self.created_values = dict(values)
        return SecretIngressSessionV1(
            "ingress-one",
            str(values["account_ref"]),
            "authorized",
            str(values["plan_digest"]),
            int(values["expected_generation"]),
            2_000_000_120.0,
            int(values["expected_generation"]),
        )

    def continue_resolve(self, **values: object) -> SecretIngressCapabilityV1:
        created = self.created_values or {
            "principal": values["principal"],
            "account_ref": values["account_ref"],
            "credential_kind": values["credential_kind"],
            "transaction_id": values.get("transaction_id"),
            "plan_digest": values.get("plan_digest") or DIGEST,
            "expected_generation": values["expected_generation"],
            "idempotency_key": "idem-session",
        }
        return SecretIngressCapabilityV1(
            "ingress-one",
            str(values["principal"]),
            str(values["account_ref"]),
            str(values["operation"]),
            str(values["credential_kind"]),
            values.get("transaction_id"),
            str(created["plan_digest"]),
            int(values["expected_generation"]),
            str(created["idempotency_key"]),
            "idem-upload",
            str(values["idempotency_key"]),
            int(values["expected_generation"]),
            int(values["expected_generation"]) + 1,
            2_000_000_120.0,
        )

    def reserve_resolve(self, session_id: str, **values: object) -> object:
        self.resolve_calls += 1
        self.last_capability = values.pop("capability", None)
        return (session_id, dict(values))

    def resolve(self, claim: object) -> SecretIngressResolutionV1:
        session_id, values = claim
        kind = values["credential_kind"]
        if kind == "openai.auth-json":
            self.last_resolution = SecretIngressResolutionV1(
                session_id, bytearray(b"openai-upload"), claim
            )
            return self.last_resolution
        if kind == "google-oauth-code":
            self.last_resolution = SecretIngressResolutionV1(
                session_id, bytearray(b"oauth-code"), claim
            )
            return self.last_resolution
        self.last_resolution = SecretIngressResolutionV1(
            session_id, bytearray(b"google-client-upload"), claim
        )
        return self.last_resolution

    def commit_resolve(self, resolution: SecretIngressResolutionV1) -> None:
        self.resolve_commits += 1
        resolution.upload.clear()

    def rollback_resolve(self, resolution: SecretIngressResolutionV1) -> None:
        self.resolve_rollbacks += 1
        resolution.upload.clear()

    def mark_resolve_unknown(self, resolution: SecretIngressResolutionV1) -> None:
        self.resolve_rollbacks += 1
        resolution.upload.clear()

    def reserve_upload(self, session_id: str, **values: object) -> object:
        claim = (session_id, dict(values))
        self.upload_claims.append(claim)
        return claim

    def put_secret(
        self,
        session_id: str,
        secret: object,
        *,
        principal: str,
        upload_claim: object,
    ) -> SecretIngressUploadReceiptV1:
        assert upload_claim in self.upload_claims
        self.put_calls += 1
        self.last_put = (session_id, secret, principal)
        return SecretIngressUploadReceiptV1(session_id, "openai-one", "consumed", 5)

    def commit_upload(self, _claim: object, _receipt: object) -> None:
        self.upload_commits += 1

    def rollback_upload(self, _claim: object) -> None:
        self.upload_rollbacks += 1


@dataclass
class Owners:
    operation_store: OperationStore
    account_registry: AccountRegistry
    openai_accounts: OpenAIAccounts
    openai_credentials: OpenAICredentials
    google_manager: GoogleManager
    google_oauth: GoogleOAuth
    quota_collector: QuotaCollector | None
    google_provisioner: GoogleProvisioner
    google_billing: GoogleBilling
    hosts: Hosts
    secret_ingress: SecretIngress


def service_at() -> tuple[MasterjetControlService, Owners]:
    owners = Owners(
        OperationStore(),
        AccountRegistry(),
        OpenAIAccounts(),
        OpenAICredentials(),
        GoogleManager(),
        GoogleOAuth(),
        QuotaCollector(),
        GoogleProvisioner(),
        GoogleBilling(),
        Hosts(),
        SecretIngress(),
    )
    service = MasterjetControlService(
        operation_store=owners.operation_store,
        openai_accounts=owners.openai_accounts,
        openai_credentials=owners.openai_credentials,
        google_manager=owners.google_manager,
        google_oauth=owners.google_oauth,
        quota_collector=owners.quota_collector,
        google_provisioner=owners.google_provisioner,
        google_billing=owners.google_billing,
        host_registry=owners.hosts,
        secret_ingress=owners.secret_ingress,
        account_registry=owners.account_registry,
    )
    return service, owners


def principal(*scopes: str, step_up: bool = False) -> AdminPrincipalV1:
    return AdminPrincipalV1("operator-one", scopes, "unix_peer", step_up)


def command(
    service: MasterjetControlService,
    operation: str,
    arguments: dict[str, object],
    scope: str,
    *,
    digest: str | None = None,
    ingress_session: object | None = None,
    oauth_code: str | None = None,
    step_up: bool = False,
    generation: int = 4,
    idempotency_key: str | None = "request-one",
) -> dict[str, object]:
    if ingress_session == "ingress-session":
        account_ref = str(arguments["account_ref"])
        credential_kind = {
            "openai.auth.apply": "openai.auth-json",
            "google.oauth.complete": "google-oauth-code",
            "google.oauth-client-import.apply": "google.oauth-client",
        }[operation]
        plan_id = arguments.get("plan_id")
        apply_key = idempotency_key
        if operation == "google.oauth.complete":
            plan_id = arguments["transaction_id"]
            apply_key = str(plan_id)
        ingress_session = SecretIngressCapabilityV1(
            "ingress-one",
            "operator-one",
            account_ref,
            operation,
            credential_kind,
            plan_id if type(plan_id) is str else None,
            digest or DIGEST,
            generation,
            "request-one",
            "idem-upload",
            str(apply_key),
            generation,
            generation + 1,
            1_120.0,
        )
    return service.command(
        principal(scope, step_up=step_up),
        operation,
        arguments,
        expected_generation=generation,
        idempotency_key=idempotency_key,  # type: ignore[arg-type]
        plan_digest=digest,
        ingress_session=ingress_session,
        oauth_code=oauth_code,
    )


def test_unknown_method_fails_before_any_owner_call() -> None:
    service, owners = service_at()

    with pytest.raises(AdminServiceError) as captured:
        service.query(principal("fleet.read"), "google.accounts.delete", {})

    assert captured.value.problem.code == "control.request_invalid"
    assert owners.google_manager.list_calls == 0


def test_google_inventory_query_uses_manager_once() -> None:
    service, owners = service_at()

    result = service.query(principal("fleet.read"), "google.accounts.list", {})

    assert result["accounts"][0]["ref"] == "google-one"  # type: ignore[index]
    assert result["accounts"][0]["inventory_generation"] == 4  # type: ignore[index]
    assert owners.google_manager.list_calls == 1


def test_google_accounts_list_projects_exact_opaque_default_oauth_client_ref() -> None:
    service, _owners = service_at()

    result = service.query(principal("fleet.read"), "google.accounts.list", {})

    account = result["accounts"][0]  # type: ignore[index]
    assert account["default_oauth_client_ref"] == "oauth-client-opaque"
    assert account["oauth_client_availability"] == "available"
    assert "client_id" not in account
    assert "client_secret" not in account


@pytest.mark.parametrize("availability", ["missing", "ambiguous", "revoked", "stale"])
def test_google_accounts_list_disables_unusable_oauth_client_binding(
    availability: str,
) -> None:
    service, owners = service_at()
    owners.google_oauth.bindings["google-one"] = (
        admin_service_module.GoogleOAuthClientBindingV1(
            "google-one",
            4,
            None,
            admin_service_module.GoogleOAuthClientAvailabilityV1(availability),
        )
    )

    account = service.query(principal("fleet.read"), "google.accounts.list", {})[
        "accounts"
    ][0]  # type: ignore[index]

    assert account["default_oauth_client_ref"] is None
    assert account["oauth_client_availability"] == availability


def test_google_accounts_list_never_accepts_cross_account_client_binding() -> None:
    service, owners = service_at()
    owners.google_oauth.bindings["google-one"] = (
        admin_service_module.GoogleOAuthClientBindingV1(
            "google-two",
            4,
            "oauth-client-foreign",
            admin_service_module.GoogleOAuthClientAvailabilityV1.AVAILABLE,
        )
    )

    account = service.query(principal("fleet.read"), "google.accounts.list", {})[
        "accounts"
    ][0]  # type: ignore[index]

    assert account["default_oauth_client_ref"] is None
    assert account["oauth_client_availability"] == "unavailable"


@pytest.mark.parametrize(
    ("operation", "arguments", "required_scope"),
    [
        ("hosts.list", {}, "fleet.host.read"),
        ("openai.accounts.list", {}, "fleet.read"),
        ("google.accounts.list", {}, "fleet.read"),
        ("google.projects.list", {"account_ref": "google-one"}, "fleet.read"),
        (
            "operations.get",
            {"account_ref": "google-one", "operation_id": "op-one"},
            "fleet.read",
        ),
    ],
)
def test_queries_require_their_exact_scope(
    operation: str, arguments: dict[str, object], required_scope: str
) -> None:
    service, _owners = service_at()

    with pytest.raises(AdminDenied, match="authority.scope_denied"):
        service.query(principal("fleet.unrelated"), operation, arguments)

    assert service.query(principal(required_scope), operation, arguments)


def test_operations_get_denies_cross_account_operation() -> None:
    service, owners = service_at()
    owners.operation_store.kind = "google.provision:google-two"

    with pytest.raises(AdminDenied, match="authority.scope_denied"):
        service.query(
            principal("fleet.read"),
            "operations.get",
            {"account_ref": "google-one", "operation_id": "op-one"},
        )

    assert owners.operation_store.calls == 1


@pytest.mark.parametrize(
    ("operation", "arguments", "scope", "expected_call"),
    (
        (
            "openai.accounts.add",
            {"account_ref": "openai-two", "label": "OpenAI Two"},
            "fleet.openai.write",
            ("add", "openai", "openai-two", "OpenAI Two", 4, "request-one"),
        ),
        (
            "openai.accounts.disable",
            {"account_ref": "openai-one"},
            "fleet.openai.write",
            ("disable", "openai", "openai-one", 4, "request-one"),
        ),
        (
            "google.accounts.add",
            {"account_ref": "google-two", "label": "Google Two"},
            "fleet.google.oauth",
            ("add", "google", "google-two", "Google Two", 4, "request-one"),
        ),
    ),
)
def test_account_commands_delegate_once_to_account_registry(
    operation: str,
    arguments: dict[str, object],
    scope: str,
    expected_call: tuple[object, ...],
) -> None:
    service, owners = service_at()

    result = command(service, operation, arguments, scope)

    assert result["account"]["ref"] == arguments["account_ref"]  # type: ignore[index]
    assert owners.account_registry.calls == [
        ("generation", operation.split(".", 1)[0]),
        expected_call,
    ]


def test_provision_apply_requires_scope_and_step_up_before_owner() -> None:
    service, owners = service_at()

    with pytest.raises(AdminDenied, match="authority.scope_denied"):
        command(
            service,
            "google.provision.apply",
            {"account_ref": "google-one"},
            "fleet.read",
            digest=DIGEST,
        )
    with pytest.raises(AdminDenied, match="authority.step_up_required"):
        command(
            service,
            "google.provision.apply",
            {"account_ref": "google-one"},
            "fleet.google.provision",
            digest=DIGEST,
        )

    assert owners.google_provisioner.apply_calls == 0


@pytest.mark.parametrize(
    ("operation", "arguments", "scope", "idempotency_key", "digest"),
    (
        (
            "openai.accounts.add",
            {"account_ref": "openai-two", "label": "OpenAI Two"},
            "fleet.openai.write",
            "idem",
            None,
        ),
        (
            "openai.accounts.disable",
            {"account_ref": "openai-one"},
            "fleet.openai.write",
            "idem",
            None,
        ),
        (
            "google.accounts.add",
            {"account_ref": "google-two", "label": "Google Two"},
            "fleet.google.oauth",
            "idem",
            None,
        ),
        (
            "openai.auth.plan",
            {"account_ref": "openai-one"},
            "fleet.openai.write",
            "idem",
            None,
        ),
        (
            "openai.auth.apply",
            {"account_ref": "openai-one"},
            "fleet.secrets.ingress",
            "idem",
            DIGEST,
        ),
        (
            "secret.ingress.create",
            {"account_ref": "openai-one", "credential_kind": "openai.auth-json"},
            "fleet.secrets.ingress",
            "idem",
            DIGEST,
        ),
        (
            "google.oauth.begin",
            {
                "account_ref": "google-one",
                "oauth_client_ref": "oauth-client-one",
                "redirect_uri": "http://127.0.0.1/callback",
                "scope_profile": "inventory",
            },
            "fleet.google.oauth",
            "idem",
            None,
        ),
        (
            "google.oauth.complete",
            {
                "account_ref": "google-one",
                "transaction_id": "transaction-one",
                "redirect_uri": "http://127.0.0.1/callback",
                "state": "state-one",
            },
            "fleet.google.oauth",
            None,
            None,
        ),
        (
            "google.oauth-client-import.plan",
            {"account_ref": "google-one"},
            "fleet.google.oauth",
            "idem",
            None,
        ),
        (
            "google.oauth-client-import.apply",
            {"account_ref": "google-one"},
            "fleet.google.oauth",
            "idem",
            DIGEST,
        ),
        (
            "google.inventory.refresh",
            {},
            "fleet.google.inventory.refresh",
            "idem",
            None,
        ),
        (
            "google.provision.plan",
            {"account_ref": "google-one"},
            "fleet.google.provision",
            "idem",
            None,
        ),
        (
            "google.provision.apply",
            {"account_ref": "google-one"},
            "fleet.google.provision",
            "idem",
            DIGEST,
        ),
        (
            "google.billing.plan",
            {
                "account_ref": "google-one",
                "project_ref": "project-one",
                "billing_ref": "billing-one",
            },
            "fleet.google.billing.bind",
            "idem",
            None,
        ),
        (
            "google.billing.apply",
            {
                "account_ref": "google-one",
                "project_ref": "project-one",
                "billing_ref": "billing-one",
                "plan_id": "plan-one",
            },
            "fleet.google.billing.bind",
            "idem",
            DIGEST,
        ),
    ),
)
def test_every_command_generation_cas_precedes_owner_dispatch(
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
    arguments: dict[str, object],
    scope: str,
    idempotency_key: str | None,
    digest: str | None,
) -> None:
    service, owners = service_at()
    owners.openai_accounts.generation = 5
    owners.openai_credentials.generation = 5
    owners.google_manager.generation = 5
    owners.google_oauth.generation = 5
    owners.account_registry.generation = 5
    owner_calls: list[str] = []

    def owner_side_effect(*_values: object) -> dict[str, object]:
        owner_calls.append(operation)
        return {"unexpected": True}

    handlers = dict(admin_service_module._COMMAND_HANDLERS)
    handlers[operation] = owner_side_effect
    monkeypatch.setattr(admin_service_module, "_COMMAND_HANDLERS", handlers)
    request = AdminRequestV1(operation, arguments, 4, idempotency_key, digest)

    with pytest.raises(AdminServiceError) as captured:
        service.handle(principal(scope, step_up=True), request)

    assert captured.value.problem.code == "credential.generation_conflict"
    assert owner_calls == []


def test_stale_google_provision_apply_never_calls_owner() -> None:
    service, owners = service_at()
    owners.google_manager.generation = 5
    owners.account_registry.generation = 5

    with pytest.raises(AdminServiceError) as captured:
        command(
            service,
            "google.provision.apply",
            {"account_ref": "google-one"},
            "fleet.google.provision",
            digest=DIGEST,
            step_up=True,
            generation=4,
        )

    assert captured.value.problem.code == "credential.generation_conflict"
    assert owners.google_provisioner.apply_calls == 0


def test_raw_secret_field_is_rejected_before_ingress_or_credential_owner() -> None:
    service, owners = service_at()
    arguments: dict[str, object] = {
        "account_ref": "openai-one",
        "auth_json": b'{"access_token":"private-marker"}',
    }

    with pytest.raises(AdminServiceError, match="control.request_invalid") as captured:
        command(
            service,
            "openai.auth.apply",
            arguments,
            "fleet.secrets.ingress",
            digest=DIGEST,
            ingress_session="ingress-session",
            step_up=True,
        )

    assert "private-marker" not in str(captured.value)
    assert owners.secret_ingress.resolve_calls == 0
    assert owners.openai_credentials.apply_calls == 0


def test_put_secret_delegates_same_buffer_with_bound_principal() -> None:
    service, owners = service_at()
    secret = bytearray(b"private-marker")
    who = principal("fleet.secrets.ingress", step_up=True)
    claim = service.reserve_secret_upload(
        who,
        "ingress-one",
        expected_generation=4,
        idempotency_key="idem-upload",
    )

    result = service.put_secret(
        who,
        "ingress-one",
        secret,
        upload_claim=claim,
    )

    assert result == {
        "session_id": "ingress-one",
        "account_ref": "openai-one",
        "state": "consumed",
        "generation": 5,
    }
    assert owners.secret_ingress.put_calls == 1
    assert owners.secret_ingress.last_put is not None
    assert owners.secret_ingress.last_put[0] == "ingress-one"
    assert owners.secret_ingress.last_put[1] is secret
    assert owners.secret_ingress.last_put[2] == "operator-one"
    assert owners.secret_ingress.upload_commits == 1


def test_put_secret_preserves_primary_signal_over_rollback_signal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, owners = service_at()
    who = principal("fleet.secrets.ingress", step_up=True)
    claim = service.reserve_secret_upload(
        who,
        "ingress-one",
        expected_generation=4,
        idempotency_key="idem-upload",
    )
    monkeypatch.setattr(
        owners.secret_ingress,
        "put_secret",
        lambda *_args, **_values: (_ for _ in ()).throw(
            KeyboardInterrupt("primary")
        ),
    )
    monkeypatch.setattr(
        owners.secret_ingress,
        "rollback_upload",
        lambda _claim: (_ for _ in ()).throw(SystemExit("cleanup")),
    )

    with pytest.raises(KeyboardInterrupt, match="primary"):
        service.put_secret(
            who,
            "ingress-one",
            bytearray(b"private-marker"),
            upload_claim=claim,
        )


def test_put_secret_without_owner_reservation_is_rejected_before_owner() -> None:
    service, owners = service_at()

    with pytest.raises(AdminServiceError, match="credential.upload_expired"):
        service.put_secret(
            principal("fleet.secrets.ingress", step_up=True),
            "ingress-one",
            bytearray(b"private-marker"),
            upload_claim=None,
        )

    assert owners.secret_ingress.put_calls == 0


def test_put_secret_requires_exact_scope_and_step_up_before_owner() -> None:
    service, owners = service_at()

    with pytest.raises(AdminDenied, match="authority.scope_denied"):
        service.put_secret(
            principal("fleet.read", step_up=True),
            "ingress-one",
            bytearray(b"private-marker"),
        )
    with pytest.raises(AdminDenied, match="authority.step_up_required"):
        service.put_secret(
            principal("fleet.secrets.ingress"),
            "ingress-one",
            bytearray(b"private-marker"),
        )

    assert owners.secret_ingress.put_calls == 0


def test_continue_secret_upload_requires_authenticated_ingress_scope() -> None:
    service, owners = service_at()

    with pytest.raises(AdminDenied, match="authority.scope_denied"):
        service.continue_secret_upload(
            principal("fleet.read"),
            "ingress-one",
            expected_generation=4,
            idempotency_key="idem-upload",
        )
    with pytest.raises(AdminServiceError, match="control.request_invalid"):
        service.continue_secret_upload(  # type: ignore[arg-type]
            object(),
            "ingress-one",
            expected_generation=4,
            idempotency_key="idem-upload",
        )

    assert owners.secret_ingress.upload_claims == []


@pytest.mark.parametrize(
    ("session_id", "secret"),
    [
        ("", bytearray(b"private-marker")),
        ("ingress-one", bytearray()),
        ("ingress-one", "private-marker"),
    ],
)
def test_put_secret_rejects_invalid_non_json_boundary_types(
    session_id: object, secret: object
) -> None:
    service, owners = service_at()

    with pytest.raises(AdminServiceError, match="control.request_invalid") as caught:
        service.put_secret(  # type: ignore[arg-type]
            principal("fleet.secrets.ingress", step_up=True),
            session_id,
            secret,
        )

    assert "private-marker" not in repr(caught.value)
    assert owners.secret_ingress.put_calls == 0


def test_openai_plan_forwards_generation_and_idempotency_once() -> None:
    service, owners = service_at()

    result = command(
        service,
        "openai.auth.plan",
        {"account_ref": "openai-one"},
        "fleet.openai.write",
    )

    assert result["plan_digest"] == DIGEST
    assert owners.openai_credentials.last_plan == ("openai-one", 4, "request-one")
    assert owners.openai_credentials.plan_calls == 1


def test_openai_plan_projects_real_owner_dto_and_adapts_digest() -> None:
    service, owners = service_at()

    def real_plan(*_args: object, **_values: object) -> AuthSyncPlanV1:
        return AuthSyncPlanV1(
            "openai-one",
            4,
            1_000.0,
            "private-nonce",
            "request-one",
            "a" * 64,
            object(),
        )

    owners.openai_credentials.plan_auth_sync = real_plan  # type: ignore[method-assign]

    result = command(
        service,
        "openai.auth.plan",
        {"account_ref": "openai-one"},
        "fleet.openai.write",
    )

    assert result == {
        "account_ref": "openai-one",
        "expected_generation": 4,
        "expires_at": 1_000.0,
        "plan_digest": DIGEST,
    }
    assert "private-nonce" not in repr(result)


def test_oauth_begin_projects_real_transaction_dto() -> None:
    service, owners = service_at()

    def real_begin(*_args: object, **_values: object) -> GoogleOAuthTransactionV1:
        return GoogleOAuthTransactionV1(
            "transaction-one",
            "google-one",
            "https://accounts.example/authorize?state=opaque",
            1_000.0,
            4,
        )

    owners.google_oauth.begin_oauth_transaction = real_begin  # type: ignore[method-assign]

    result = command(
        service,
        "google.oauth.begin",
        {
            "account_ref": "google-one",
            "oauth_client_ref": "client-one",
            "redirect_uri": "http://127.0.0.1/callback",
            "scope_profile": "inventory_readonly",
        },
        "fleet.google.oauth",
        step_up=True,
    )

    assert result["id"] == "transaction-one"
    assert (
        result["authorization_url"] == "https://accounts.example/authorize?state=opaque"
    )
    assert result["inventory_generation"] == 4


def test_oauth_client_plan_projects_real_owner_dto_and_adapts_digest() -> None:
    service, owners = service_at()

    def real_plan(*_args: object, **_values: object) -> GoogleOAuthClientImportPlanV1:
        return GoogleOAuthClientImportPlanV1(
            "oauth-import-one",
            "google-one",
            4,
            1_000.0,
            "request-one",
            "a" * 64,
        )

    owners.google_oauth.plan_oauth_client_import = real_plan  # type: ignore[method-assign]

    result = command(
        service,
        "google.oauth-client-import.plan",
        {"account_ref": "google-one"},
        "fleet.google.oauth",
    )

    assert result == {
        "id": "oauth-import-one",
        "account_ref": "google-one",
        "expected_generation": 4,
        "expires_at": 1_000.0,
        "plan_digest": DIGEST,
    }


def test_openai_apply_resolves_bound_ingress_and_calls_owner_once() -> None:
    service, owners = service_at()

    result = command(
        service,
        "openai.auth.apply",
        {"account_ref": "openai-one"},
        "fleet.secrets.ingress",
        digest=DIGEST,
        ingress_session="ingress-session",
        step_up=True,
    )

    assert result["state"] == "succeeded"
    assert owners.secret_ingress.resolve_calls == 1
    assert owners.openai_credentials.apply_calls == 1


def test_post_effect_journal_failure_is_chained_behind_canonical_problem() -> None:
    """Break caught: journal fault must not replace post-effect retry contract."""

    service, owners = service_at()
    journal_error = RuntimeError("private-journal-audit-marker")
    effect_calls = 0

    def fail_after_effect(*_args: object) -> None:
        nonlocal effect_calls
        effect_calls += 1
        raise RuntimeError("private-post-effect-marker")

    def fail_unknown_journal(resolution: SecretIngressResolutionV1) -> None:
        resolution.upload.clear()
        raise journal_error

    owners.openai_credentials.apply_auth_sync = fail_after_effect  # type: ignore[method-assign]
    owners.secret_ingress.mark_resolve_unknown = fail_unknown_journal  # type: ignore[method-assign]

    with pytest.raises(AdminServiceError) as captured:
        command(
            service,
            "openai.auth.apply",
            {"account_ref": "openai-one"},
            "fleet.secrets.ingress",
            digest=DIGEST,
            ingress_session="ingress-session",
            step_up=True,
        )

    assert captured.value.problem.code == "control.owner_unavailable"
    assert captured.value.problem.effect == "Action outcome is unknown"
    assert captured.value.problem.action == (
        "Retry the identical request to reconcile outcome"
    )
    assert captured.value.problem.retryable is True
    assert captured.value.__cause__ is journal_error
    assert effect_calls == 1


def test_openai_plan_precondition_failure_rolls_back_and_wipes_resolution() -> None:
    """Break caught: failed plan lookup must not strand secret or owner claim."""

    service, owners = service_at()
    owners.openai_credentials.resolve_error = True

    with pytest.raises(AdminServiceError, match="control.owner_unavailable"):
        command(
            service,
            "openai.auth.apply",
            {"account_ref": "openai-one"},
            "fleet.secrets.ingress",
            digest=DIGEST,
            ingress_session="ingress-session",
            step_up=True,
        )

    assert owners.secret_ingress.resolve_rollbacks == 1
    assert owners.secret_ingress.last_resolution is not None
    assert owners.secret_ingress.last_resolution.upload == bytearray()


def test_oauth_code_decodes_mutable_buffer_without_bytes_copy(monkeypatch) -> None:
    """Break caught: mutable OAuth code must not cross a project `bytes()` copy."""

    def forbidden_bytes(_value):
        raise AssertionError("immutable project copy")

    monkeypatch.setattr(admin_service_module, "bytes", forbidden_bytes, raising=False)
    raw = bytearray(b"oauth-code")

    code, wipe = admin_service_module._oauth_code(raw)  # noqa: SLF001

    assert code == "oauth-code"
    assert wipe is raw


@pytest.mark.parametrize(
    ("operation", "arguments", "scope", "digest", "extra", "expected"),
    [
        (
            "secret.ingress.create",
            {"account_ref": "openai-one", "credential_kind": "openai.auth-json"},
            "fleet.secrets.ingress",
            DIGEST,
            {"step_up": True},
            "ingress",
        ),
        (
            "google.oauth.begin",
            {
                "account_ref": "google-one",
                "oauth_client_ref": "client-one",
                "redirect_uri": "http://127.0.0.1/callback",
                "scope_profile": "inventory_readonly",
            },
            "fleet.google.oauth",
            None,
            {"step_up": True},
            "oauth-begin",
        ),
        (
            "google.oauth.complete",
            {
                "account_ref": "google-one",
                "transaction_id": "transaction-one",
                "redirect_uri": "http://127.0.0.1/callback",
                "state": "state-one",
            },
            "fleet.google.oauth",
            None,
            {
                "ingress_session": "ingress-session",
                "step_up": True,
                "idempotency_key": None,
            },
            "oauth-complete",
        ),
        (
            "google.oauth-client-import.plan",
            {"account_ref": "google-one"},
            "fleet.google.oauth",
            None,
            {},
            "oauth-client-plan",
        ),
        (
            "google.oauth-client-import.apply",
            {"account_ref": "google-one"},
            "fleet.google.oauth",
            DIGEST,
            {"ingress_session": "ingress-session", "step_up": True},
            "oauth-client-apply",
        ),
        (
            "google.inventory.refresh",
            {},
            "fleet.google.inventory.refresh",
            None,
            {},
            "inventory",
        ),
        (
            "google.provision.plan",
            {"account_ref": "google-one"},
            "fleet.google.provision",
            None,
            {},
            "provision-plan",
        ),
        (
            "google.provision.apply",
            {"account_ref": "google-one"},
            "fleet.google.provision",
            DIGEST,
            {"step_up": True},
            "provision-apply",
        ),
        (
            "google.billing.plan",
            {
                "account_ref": "google-one",
                "project_ref": "project-one",
                "billing_ref": "billing-one",
            },
            "fleet.google.billing.bind",
            None,
            {},
            "billing-plan",
        ),
        (
            "google.billing.apply",
            {
                "account_ref": "google-one",
                "project_ref": "project-one",
                "billing_ref": "billing-one",
                "plan_id": "billing-plan-one",
            },
            "fleet.google.billing.bind",
            DIGEST,
            {"step_up": True},
            "billing-apply",
        ),
    ],
)
def test_command_dispatch_calls_only_the_selected_owner_once(
    operation: str,
    arguments: dict[str, object],
    scope: str,
    digest: str | None,
    extra: dict[str, object],
    expected: str,
) -> None:
    service, owners = service_at()

    result = command(
        service,
        operation,
        arguments,
        scope,
        digest=digest,
        **extra,  # type: ignore[arg-type]
    )

    assert result
    counts = {
        "ingress": owners.secret_ingress.create_calls,
        "oauth-begin": owners.google_oauth.calls.count("begin"),
        "oauth-complete": owners.google_oauth.calls.count("complete"),
        "oauth-client-plan": owners.google_oauth.calls.count("client-plan"),
        "oauth-client-apply": owners.google_oauth.calls.count("client-apply"),
        "inventory": owners.google_manager.reload_calls,
        "provision-plan": owners.google_provisioner.plan_calls,
        "provision-apply": owners.google_provisioner.apply_calls,
        "billing-plan": owners.google_billing.plan_calls,
        "billing-apply": owners.google_billing.apply_calls,
    }
    assert counts[expected] == 1
    assert sum(counts.values()) == 1


class PrivateOwnerFailure(Exception):
    @property
    def code(self) -> str:
        raise RuntimeError("private-marker /private/root")

    def __str__(self) -> str:
        return "private-marker /private/root"


def test_owner_error_is_hive_problem_and_never_echoes_foreign_exception() -> None:
    service, owners = service_at()

    def fail() -> tuple[dict[str, object], ...]:
        raise PrivateOwnerFailure()

    owners.google_manager.list_accounts = fail  # type: ignore[method-assign]

    with pytest.raises(AdminServiceError) as captured:
        service.query(principal("fleet.read"), "google.accounts.list", {})

    assert captured.value.problem.code == "control.owner_unavailable"
    rendered = repr(captured.value) + str(captured.value)
    assert "private-marker" not in rendered
    assert "/private/root" not in rendered
    assert captured.value.__context__ is None


@pytest.mark.parametrize("signal_type", [KeyboardInterrupt, SystemExit])
def test_handle_propagates_owner_control_signal_unchanged(signal_type) -> None:
    """Break caught: process-control signals must escape owner dispatch."""

    service, owners = service_at()
    signal = signal_type("stop-owner-dispatch")

    def stop() -> tuple[dict[str, object], ...]:
        raise signal

    owners.google_manager.list_accounts = stop  # type: ignore[method-assign]

    with pytest.raises(signal_type) as captured:
        service.query(principal("fleet.read"), "google.accounts.list", {})

    assert captured.value is signal


@pytest.mark.parametrize("signal_type", [KeyboardInterrupt, SystemExit])
def test_post_effect_journal_control_signal_propagates_unchanged(signal_type) -> None:
    """Break caught: post-effect journal signal must escape public handle."""

    service, owners = service_at()
    signal = signal_type("stop-post-effect-journal")
    effect_calls = 0

    def fail_after_effect(*_args: object) -> None:
        nonlocal effect_calls
        effect_calls += 1
        raise RuntimeError("private-post-effect-marker")

    def stop_unknown_journal(resolution: SecretIngressResolutionV1) -> None:
        resolution.upload.clear()
        raise signal

    owners.openai_credentials.apply_auth_sync = fail_after_effect  # type: ignore[method-assign]
    owners.secret_ingress.mark_resolve_unknown = stop_unknown_journal  # type: ignore[method-assign]

    with pytest.raises(signal_type) as captured:
        command(
            service,
            "openai.auth.apply",
            {"account_ref": "openai-one"},
            "fleet.secrets.ingress",
            digest=DIGEST,
            ingress_session="ingress-session",
            step_up=True,
        )

    assert captured.value is signal
    assert effect_calls == 1


def test_concurrent_queries_delegate_exactly_once_per_request() -> None:
    service, owners = service_at()

    def query_once(_index: int) -> dict[str, object]:
        return service.query(principal("fleet.read"), "google.accounts.list", {})

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(query_once, range(32)))

    assert all(result["accounts"][0]["ref"] == "google-one" for result in results)  # type: ignore[index]
    assert owners.google_manager.list_calls == 32


def test_missing_quota_collector_fails_closed_without_fake_default() -> None:
    service, owners = service_at()
    service = MasterjetControlService(
        operation_store=owners.operation_store,
        openai_accounts=owners.openai_accounts,
        openai_credentials=owners.openai_credentials,
        google_manager=owners.google_manager,
        google_oauth=owners.google_oauth,
        quota_collector=None,
        google_provisioner=owners.google_provisioner,
        google_billing=owners.google_billing,
        host_registry=owners.hosts,
        secret_ingress=owners.secret_ingress,
    )

    with pytest.raises(AdminServiceError, match="control.owner_unavailable"):
        command(
            service,
            "google.provision.plan",
            {"account_ref": "google-one"},
            "fleet.google.provision",
        )

    assert owners.google_provisioner.plan_calls == 0


def test_oauth_begin_forwards_durable_idempotency_binding() -> None:
    service, owners = service_at()

    command(
        service,
        "google.oauth.begin",
        {
            "account_ref": "google-one",
            "oauth_client_ref": "client-one",
            "redirect_uri": "http://127.0.0.1/callback",
            "scope_profile": "inventory_readonly",
        },
        "fleet.google.oauth",
        step_up=True,
    )

    assert owners.google_oauth.last_begin == (
        "google-one",
        {
            "oauth_client_ref": "client-one",
            "redirect_uri": "http://127.0.0.1/callback",
            "scope_profile": GoogleOAuthProfileIdV1.INVENTORY_READONLY,
            "expected_generation": 4,
            "idempotency_key": "request-one",
            "principal": "operator-one",
        },
    )


def test_global_inventory_refresh_replays_durable_receipt_after_restart(
    tmp_path,
) -> None:
    service, owners = service_at()
    service._operation_store = AdminOperationStore.for_test(tmp_path)

    first = command(
        service,
        "google.inventory.refresh",
        {},
        "fleet.google.inventory.refresh",
    )
    restarted, _restarted_owners = service_at()
    restarted._operation_store = AdminOperationStore.for_test(tmp_path)
    restarted._google_manager = owners.google_manager
    second = command(
        restarted,
        "google.inventory.refresh",
        {},
        "fleet.google.inventory.refresh",
    )

    assert second == first
    assert first["state"] == "succeeded"
    assert first["resulting_generation"] == 5
    assert owners.google_manager.reload_calls == 1


def test_global_inventory_refresh_rejects_stale_generation_before_reload(
    tmp_path,
) -> None:
    service, owners = service_at()
    service._operation_store = AdminOperationStore.for_test(tmp_path)
    owners.google_manager.generation = 5

    with pytest.raises(AdminServiceError):
        command(
            service,
            "google.inventory.refresh",
            {},
            "fleet.google.inventory.refresh",
            generation=4,
            idempotency_key="stale-refresh",
        )

    assert owners.google_manager.reload_calls == 0
    assert not (tmp_path / "admin-operations" / "operations.json").exists()


def test_global_inventory_refresh_owner_failure_replays_terminal_receipt(
    tmp_path,
) -> None:
    service, owners = service_at()
    service._operation_store = AdminOperationStore.for_test(tmp_path)

    def fail_reload(*, expected_generation: int) -> GoogleAccountInventoryStatusV1:
        assert expected_generation == 4
        owners.google_manager.reload_calls += 1
        raise GoogleAccountInventoryError("credential.inventory_reload_failed")

    owners.google_manager.reload = fail_reload  # type: ignore[method-assign]

    with pytest.raises(AdminServiceError) as captured:
        command(
            service,
            "google.inventory.refresh",
            {},
            "fleet.google.inventory.refresh",
            idempotency_key="failed-refresh",
        )

    live_replay = command(
        service,
        "google.inventory.refresh",
        {},
        "fleet.google.inventory.refresh",
        idempotency_key="failed-refresh",
    )
    restarted, _restarted_owners = service_at()
    restarted._operation_store = AdminOperationStore.for_test(tmp_path)
    restarted._google_manager = owners.google_manager
    restart_replay = command(
        restarted,
        "google.inventory.refresh",
        {},
        "fleet.google.inventory.refresh",
        idempotency_key="failed-refresh",
    )

    assert captured.value.problem.code == "credential.inventory_reload_failed"
    assert live_replay == restart_replay
    assert live_replay["state"] == "failed"
    assert live_replay["failed_count"] == 1
    assert live_replay["reason_codes"] == ["credential.inventory_reload_failed"]
    assert owners.google_manager.reload_calls == 1


def test_billing_service_forwards_exact_request_owner_binding() -> None:
    service, owners = service_at()

    command(
        service,
        "google.billing.plan",
        {
            "account_ref": "google-one",
            "project_ref": "project-one",
            "billing_ref": "billing-one",
        },
        "fleet.google.billing.bind",
    )
    command(
        service,
        "google.billing.apply",
        {
            "account_ref": "google-one",
            "project_ref": "project-one",
            "billing_ref": "billing-one",
            "plan_id": "billing-plan-one",
        },
        "fleet.google.billing.bind",
        digest=DIGEST,
        step_up=True,
    )

    assert owners.google_billing.last_plan is not None
    assert owners.google_billing.last_plan == {
        "account_ref": "google-one",
        "project_ref": "project-one",
        "billing_ref": "billing-one",
        "expected_generation": 4,
        "idempotency_key": "request-one",
    }
    assert owners.google_billing.last_apply is not None
    assert owners.google_billing.last_apply == (
        "billing-plan-one",
        {
            "account_ref": "google-one",
            "project_ref": "project-one",
            "billing_ref": "billing-one",
            "expected_generation": 4,
            "confirmed_digest": DIGEST,
            "idempotency_key": "request-one",
        },
    )


def test_unknown_owner_projection_fails_closed_without_credential_echo() -> None:
    service, owners = service_at()
    marker = "Bearer private-owner-regression"
    owners.openai_credentials.plan_auth_sync = (  # type: ignore[method-assign]
        lambda *_args, **_values: PublicValue({"note": marker})
    )

    with pytest.raises(AdminServiceError) as captured:
        command(
            service,
            "openai.auth.plan",
            {"account_ref": "openai-one"},
            "fleet.openai.write",
        )

    assert captured.value.problem.code == "control.response_private"
    assert marker not in repr(captured.value)


def test_partial_owner_error_reports_partial_effect_without_private_echo() -> None:
    service, owners = service_at()
    partial = GoogleBillingReceiptV1(
        "billing-plan-one", "partial", 1, 0, 1, 0, "billing.provider_failed"
    )

    def fail(*_args: object, **_values: object) -> PublicValue:
        raise GoogleBillingError("billing.provider_failed", partial=partial)

    owners.google_billing.apply_billing_binding = fail  # type: ignore[method-assign]

    with pytest.raises(AdminServiceError) as captured:
        command(
            service,
            "google.billing.apply",
            {
                "account_ref": "google-one",
                "project_ref": "project-one",
                "billing_ref": "billing-one",
                "plan_id": "billing-plan-one",
            },
            "fleet.google.billing.bind",
            digest=DIGEST,
            step_up=True,
        )

    assert captured.value.problem.code == "billing.provider_failed"
    assert captured.value.problem.effect == "Action may be partially completed"
    assert "billing-plan-one" not in repr(captured.value)


def test_unknown_coded_owner_error_is_not_trusted_and_has_unknown_effect() -> None:
    service, owners = service_at()

    class UnknownOwnerError(Exception):
        code = "billing.provider_failed"

    def fail() -> tuple[dict[str, object], ...]:
        raise UnknownOwnerError("private-owner-marker")

    owners.google_manager.list_accounts = fail  # type: ignore[method-assign]

    with pytest.raises(AdminServiceError) as captured:
        service.query(principal("fleet.read"), "google.accounts.list", {})

    assert captured.value.problem.code == "control.owner_unavailable"
    assert captured.value.problem.effect == "Action outcome is unknown"
    assert "private-owner-marker" not in repr(captured.value)


def test_unknown_ingress_kind_fails_before_owner_call() -> None:
    service, owners = service_at()

    with pytest.raises(AdminServiceError, match="control.request_invalid"):
        command(
            service,
            "secret.ingress.create",
            {
                "account_ref": "google-one",
                "credential_kind": "future.secret-format",
            },
            "fleet.secrets.ingress",
            digest=DIGEST,
            step_up=True,
        )

    assert owners.secret_ingress.create_calls == 0
