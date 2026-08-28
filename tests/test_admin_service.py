from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from threading import Lock

import pytest

from codex_master.admin_contracts import AdminPrincipalV1, OperationV1
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

    def list_accounts(self) -> tuple[OpenAIAccountSummaryV1, ...]:
        self.calls += 1
        return (OpenAIAccountSummaryV1("openai-one", 4),)


class OpenAICredentials:
    def __init__(self) -> None:
        self.plan_calls = 0
        self.apply_calls = 0
        self.last_plan: tuple[object, ...] | None = None

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
        assert upload == "openai-upload"
        return AuthSyncReceiptV1("openai-one", 5, "a" * 64)


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
        self.calls: list[str] = []
        self.last_begin: tuple[str, dict[str, object]] | None = None

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
        assert ingress_session == "google-client-upload"
        return GoogleOAuthClientImportReceiptV1(
            "google-one", "client-one", "Quiet Client", 4, "a" * 64
        )


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

    def create_session(self, **values: object) -> SecretIngressSessionV1:
        self.create_calls += 1
        return SecretIngressSessionV1(
            "ingress-one", str(values["account_ref"]), "authorized"
        )

    def resolve(self, session: object, **values: object) -> tuple[object, object]:
        self.resolve_calls += 1
        assert session == "ingress-session"
        if values["credential_kind"] == "openai.auth-json":
            return "openai-plan", "openai-upload"
        return "google-client-plan", "google-client-upload"


@dataclass
class Owners:
    operation_store: OperationStore
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
                "oauth_code": "oauth-code",
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


class PrivateOwnerFailure(BaseException):
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
