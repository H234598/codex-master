"""Transport-independent Masterjet administration service boundary."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
import re
from types import MappingProxyType
from typing import Any, Never, Protocol, cast
import urllib.parse
import uuid

from .admin_contracts import (
    ADMIN_OPERATION_CATALOG,
    ADMIN_OPERATION_CATALOG_DIGEST,
    ADMIN_OPERATION_METADATA,
    AdminContractError,
    AdminPrincipalV1,
    AdminRequestV1,
    HiveProblemV1,
    agent_result_kind,
    public_admin_result,
    public_operation_status,
    public_admin_text,
)
from .admin_hosts import ControlHostV1, HostRegistry, HostRegistryError
from .admin_operations import AdminOperationError, AdminOperationStore
from .agent_operations import AgentOperationError, AgentOperationStore
from .credential_vault import CredentialVault
from .google_account_inventory import GoogleAccountInventoryError
from .google_account_inventory_manager import (
    GoogleAccountInventoryManager,
    GoogleAccountInventoryStatusV1,
)
from .google_billing_service import (
    GoogleBillingError,
    GoogleBillingPlanV1,
    GoogleBillingReceiptV1,
    GoogleBillingService,
)
from .google_cloud_provisioner import (
    FillToQuotaPlan,
    GoogleCloudProvisionerError,
    ProvisionPartialReceipt,
    ProvisionReceipt,
)
from .google_oauth_authorization import GoogleOAuthProfileIdV1
from .google_oauth_session import (
    GoogleOAuthClientAvailabilityV1,
    GoogleOAuthClientBindingV1,
    GoogleOAuthClientImportPlanV1,
    GoogleOAuthClientImportReceiptV1,
    GoogleOAuthControlService,
    GoogleOAuthSessionError,
    GoogleOAuthSessionReceipt,
    GoogleOAuthTransactionV1,
)
from .openai_credential_service import (
    AuthSyncPlanV1,
    AuthSyncReceiptV1,
    OpenAICredentialError,
    OpenAICredentialService,
)
from .fleet_service import (
    FleetConflictError,
    OllamaApplyResultV1,
    OllamaFleetPlanV1,
)
from .ollama_registry import OllamaInstanceV1, OllamaModelV1
from .ollama_runtime import OllamaReadinessStatus
from .admin_contracts import OperationV1


QUERY_SCOPES = MappingProxyType(
    {
        operation: metadata.scope
        for operation, metadata in ADMIN_OPERATION_METADATA.items()
        if not metadata.command and metadata.scope is not None
    }
)

COMMAND_SCOPES = MappingProxyType(
    {
        operation: metadata.scope
        for operation, metadata in ADMIN_OPERATION_METADATA.items()
        if metadata.command and metadata.scope is not None
    }
)

_STEP_UP_OPERATIONS = frozenset(
    {
        "openai.auth.apply",
        "secret.ingress.create",
        "google.oauth.begin",
        "google.oauth.complete",
        "google.oauth-client-import.apply",
        "google.quota-evidence.sync",
        "google.provision.apply",
        "google.billing.apply",
    }
)
_INGRESS_APPLY_KINDS = MappingProxyType(
    {
        "openai.auth.apply": "openai.auth-json",
        "google.oauth.complete": "google-oauth-code",
        "google.oauth-client-import.apply": "google.oauth-client",
    }
)
_CODE = re.compile(r"[a-z][a-z0-9_.-]{0,127}\Z", re.ASCII)
_SESSION_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z", re.ASCII)
_HEX_DIGEST = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_GOOGLE_OAUTH_STATES = frozenset(
    {"needs_auth", "pending", "ready", "repair_required", "stale", "unavailable"}
)
_GOOGLE_QUOTA_STATES = frozenset({"exhausted", "fresh", "unavailable"})
_FORBIDDEN_ARGUMENT_KEYS = frozenset(
    {
        "access_token",
        "auth_json",
        "authorization",
        "client_secret",
        "cookie",
        "password",
        "payload",
        "raw_body",
        "refresh_token",
        "secret",
    }
)


class OpenAIAccountsPort(Protocol):
    def list_accounts(self) -> Sequence[OpenAIAccountSummaryV1]: ...


class AccountRegistryPort(Protocol):
    def current_generation(self, provider: str) -> int: ...

    def add_account(
        self,
        provider: str,
        account_ref: str,
        label: str,
        *,
        expected_generation: int,
        idempotency_key: str,
    ) -> Mapping[str, object]: ...

    def disable_account(
        self,
        provider: str,
        account_ref: str,
        *,
        expected_generation: int,
        idempotency_key: str,
    ) -> Mapping[str, object]: ...


class QuotaCollectorPort(Protocol):
    def collect(self, account_ref: str, *, expected_generation: int) -> object: ...

    def quota_state(self, account_ref: str, *, expected_generation: int) -> str: ...

    def sync(self, account_ref: str, **values: object) -> Mapping[str, object]: ...


class GoogleProvisionerPort(Protocol):
    def plan(
        self,
        account_ref: str,
        *,
        expected_generation: int,
        idempotency_key: str | None,
        quota_evidence: object,
    ) -> FillToQuotaPlan: ...

    def apply(
        self,
        account_ref: str,
        *,
        expected_generation: int,
        idempotency_key: str,
        plan_digest: str,
    ) -> ProvisionReceipt | ProvisionPartialReceipt: ...


class OllamaFleetPort(Protocol):
    def ollama_generation(self) -> int: ...

    def ollama_models(self) -> Sequence[OllamaModelV1]: ...

    def ollama_instances(self) -> Sequence[OllamaInstanceV1]: ...

    def plan_ollama_instance(
        self, instance: OllamaInstanceV1, *, expected_generation: int
    ) -> OllamaFleetPlanV1: ...

    def apply_ollama_instance(
        self, plan_id: str, *, expected_generation: int
    ) -> OllamaApplyResultV1: ...

    def probe_ollama_instance(
        self, instance_ref: str, *, expected_generation: int
    ) -> OllamaReadinessStatus: ...


class HostProbePort(Protocol):
    def probe(
        self,
        host_ref: str,
        *,
        expected_generation: int,
        idempotency_key: str,
    ) -> OperationV1: ...


class SecretIngressPort(Protocol):
    def create_session(self, **values: object) -> SecretIngressSessionV1: ...

    def reserve_upload(self, session_id: str, **values: object) -> object: ...

    def put_secret(
        self,
        session_id: str,
        secret: bytes | bytearray | memoryview,
        *,
        principal: str,
        upload_claim: object,
    ) -> SecretIngressUploadReceiptV1: ...

    def commit_upload(
        self, claim: object, receipt: SecretIngressUploadReceiptV1
    ) -> None: ...

    def rollback_upload(self, claim: object) -> None: ...

    def continue_resolve(self, **values: object) -> SecretIngressCapabilityV1: ...

    def reserve_resolve(self, session_id: str, **values: object) -> object: ...

    def resolve(self, claim: object) -> SecretIngressResolutionV1: ...

    def commit_resolve(self, resolution: SecretIngressResolutionV1) -> None: ...

    def rollback_resolve(self, resolution: SecretIngressResolutionV1) -> None: ...

    def mark_resolve_unknown(self, resolution: SecretIngressResolutionV1) -> None: ...


@dataclass(frozen=True, slots=True)
class OpenAIAccountSummaryV1:
    ref: str
    generation: int


@dataclass(frozen=True, slots=True)
class GoogleAccountSummaryV1:
    ref: str
    label: str | None
    enabled: bool
    subject_bound: bool
    oauth_state: str
    inventory_generation: int
    quota_state: str
    project_count: int
    billing_count: int
    billing_refs: tuple[str, ...]
    reload_state: str
    default_oauth_client_ref: str | None
    oauth_client_availability: str


@dataclass(frozen=True, slots=True)
class SecretIngressSessionV1:
    id: str
    account_ref: str
    state: str
    plan_digest: str = ""
    expected_generation: int = 0
    expires_at: float = 0.0
    session_generation: int = 0


@dataclass(frozen=True, slots=True)
class SecretIngressUploadReceiptV1:
    session_id: str
    account_ref: str
    state: str
    generation: int


@dataclass(slots=True, repr=False)
class SecretIngressResolutionV1:
    session_id: str
    upload: bytearray
    claim: object
    reconcile_only: bool = False

    def __repr__(self) -> str:
        return "SecretIngressResolutionV1(<redacted>)"


class SecretIngressOwnerError(ValueError):
    """Code-only concrete ingress-owner failure."""

    __slots__ = ("code",)

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class SecretIngressCapabilityV1:
    """Non-secret, exact one-flow capability resolved by ingress owner."""

    session_id: str
    subject: str
    account_ref: str
    operation: str
    credential_kind: str
    transaction_id: str | None
    plan_digest: str
    expected_generation: int
    create_idempotency_key: str
    upload_idempotency_key: str
    apply_idempotency_key: str
    session_generation: int
    receipt_generation: int
    expires_at: float
    reconcile_only: bool = False


class AdminServiceError(Exception):
    """Public code-only service failure carrying one validated problem."""

    __slots__ = ("problem",)

    def __init__(self, problem: HiveProblemV1) -> None:
        self.problem = problem
        super().__init__(problem.code)

    def __repr__(self) -> str:
        return f"{type(self).__name__}({self.problem.code!r})"

    def __str__(self) -> str:
        return self.problem.code


class AdminDenied(AdminServiceError):
    """Authorization or account-isolation denial."""


class MasterjetControlService:
    """One explicit dispatch table over injected administration owners."""

    def __init__(
        self,
        *,
        operation_store: AdminOperationStore,
        agent_operations: AgentOperationStore | None = None,
        openai_accounts: OpenAIAccountsPort | None,
        openai_credentials: OpenAICredentialService | None,
        google_manager: GoogleAccountInventoryManager,
        google_oauth: GoogleOAuthControlService | None,
        quota_collector: QuotaCollectorPort | None,
        google_provisioner: GoogleProvisionerPort | None,
        google_billing: GoogleBillingService | None,
        host_registry: HostRegistry,
        secret_ingress: SecretIngressPort | None,
        account_registry: AccountRegistryPort | None = None,
        ollama_fleet: OllamaFleetPort | None = None,
        host_probe: HostProbePort | None = None,
    ) -> None:
        self._operation_store = operation_store
        self._agent_operations = agent_operations
        self._openai_accounts = openai_accounts
        self._openai_credentials = openai_credentials
        self._google_manager = google_manager
        self._google_oauth = google_oauth
        self._quota_collector = quota_collector
        self._google_provisioner = google_provisioner
        self._google_billing = google_billing
        self._host_registry = host_registry
        self._secret_ingress = secret_ingress
        self._account_registry = account_registry
        self._ollama_fleet = ollama_fleet
        self._host_probe = host_probe
        self._ollama_plan_digests: dict[str, str] = {}

    @classmethod
    def with_admin_secret_ingress(
        cls,
        *,
        secret_ingress_state_root: Path,
        secret_ingress_vault: CredentialVault,
        operation_store: AdminOperationStore,
        openai_accounts: OpenAIAccountsPort | None,
        openai_credentials: OpenAICredentialService | None,
        google_manager: GoogleAccountInventoryManager,
        google_oauth_factory: Callable[
            [SecretIngressPort], GoogleOAuthControlService | None
        ],
        quota_collector: QuotaCollectorPort | None,
        google_provisioner: GoogleProvisionerPort | None,
        google_billing: GoogleBillingService | None,
        host_registry: HostRegistry,
        clock: Callable[[], float],
    ) -> MasterjetControlService:
        """Compose one concrete ingress owner with the existing business owners."""

        from .admin_secret_ingress import AdminSecretIngressOwner

        ingress = AdminSecretIngressOwner(
            secret_ingress_state_root,
            vault=secret_ingress_vault,
            clock=clock,
        )
        ingress_port = cast(SecretIngressPort, ingress)
        google_oauth = google_oauth_factory(ingress_port)
        return cls(
            operation_store=operation_store,
            openai_accounts=openai_accounts,
            openai_credentials=openai_credentials,
            google_manager=google_manager,
            google_oauth=google_oauth,
            quota_collector=quota_collector,
            google_provisioner=google_provisioner,
            google_billing=google_billing,
            host_registry=host_registry,
            secret_ingress=ingress_port,
        )

    def query(
        self,
        principal: AdminPrincipalV1,
        operation: str,
        arguments: Mapping[str, object],
    ) -> dict[str, object]:
        """Validate a query through ``AdminRequestV1`` and use ``handle``."""

        try:
            request = AdminRequestV1(operation, arguments, None, None, None)
        except BaseException:
            raise _service_error("control.request_invalid") from None
        return self.handle(principal, request)

    def put_secret(
        self,
        principal: AdminPrincipalV1,
        session_id: str,
        secret: bytes | bytearray | memoryview,
        *,
        upload_claim: object | None = None,
    ) -> dict[str, object]:
        """Consume one secret outside all JSON control request paths."""

        if type(principal) is not AdminPrincipalV1:
            raise _service_error("control.request_invalid")
        if "fleet.secrets.ingress" not in principal.scopes:
            raise _denied("authority.scope_denied")
        if not principal.step_up:
            raise _denied("authority.step_up_required")
        if type(session_id) is not str or _SESSION_ID.fullmatch(session_id) is None:
            raise _service_error("control.request_invalid")
        secret = _secret_value(secret)
        if upload_claim is None or type(upload_claim) in {bytes, bytearray, memoryview}:
            raise _service_error("credential.upload_expired")
        ingress = _required(self._secret_ingress)
        result: SecretIngressUploadReceiptV1 | None = None
        try:
            result = ingress.put_secret(
                session_id,
                secret,
                principal=principal.subject,
                upload_claim=upload_claim,
            )
            ingress.commit_upload(upload_claim, result)
        except AdminServiceError:
            raise
        except BaseException as error:
            if result is None:
                try:
                    ingress.rollback_upload(upload_claim)
                except BaseException as cleanup_error:
                    if isinstance(error, Exception) and not isinstance(
                        cleanup_error, Exception
                    ):
                        raise
            if not isinstance(error, Exception):
                raise
            owner_error = _owner_service_error(error)
            del error
            raise owner_error from None
        return _public_mapping(_serialize_ingress_upload_receipt(result))

    def reserve_secret_upload(
        self,
        principal: AdminPrincipalV1,
        session_id: str,
        *,
        expected_generation: int,
        idempotency_key: str,
    ) -> object:
        """Reserve one durable upload capability before reading secret bytes."""

        if type(principal) is not AdminPrincipalV1:
            raise _service_error("control.request_invalid")
        if "fleet.secrets.ingress" not in principal.scopes:
            raise _denied("authority.scope_denied")
        if not principal.step_up:
            raise _denied("authority.step_up_required")
        if (
            type(session_id) is not str
            or _SESSION_ID.fullmatch(session_id) is None
            or type(expected_generation) is not int
            or not 0 <= expected_generation <= 2**63 - 1
            or type(idempotency_key) is not str
            or _SESSION_ID.fullmatch(idempotency_key) is None
        ):
            raise _service_error("control.request_invalid")
        ingress = _required(self._secret_ingress)
        try:
            return ingress.reserve_upload(
                session_id,
                principal=principal.subject,
                expected_generation=expected_generation,
                idempotency_key=idempotency_key,
            )
        except Exception as error:
            owner_error = _owner_service_error(error)
            del error
            raise owner_error from None

    def continue_secret_upload(
        self,
        principal: AdminPrincipalV1,
        session_id: str,
        *,
        expected_generation: int,
        idempotency_key: str,
    ) -> object:
        """Resume one upload from durable principal/session authority."""

        if type(principal) is not AdminPrincipalV1:
            raise _service_error("control.request_invalid")
        continued = replace(principal, step_up=True)
        return self.reserve_secret_upload(
            continued,
            session_id,
            expected_generation=expected_generation,
            idempotency_key=idempotency_key,
        )

    def _continued_secret_apply(
        self, principal: AdminPrincipalV1, request: AdminRequestV1
    ) -> SecretIngressCapabilityV1 | None:
        """Recover exact durable ingress authority for one apply dispatch."""

        kind = _INGRESS_APPLY_KINDS[request.operation]
        account_ref = request.arguments.get("account_ref")
        transaction_id = request.arguments.get("transaction_id")
        apply_key = request.idempotency_key or transaction_id
        if type(account_ref) is not str or type(apply_key) is not str:
            raise _service_error("control.request_invalid")
        ingress = _required(self._secret_ingress)
        try:
            return cast(
                SecretIngressCapabilityV1,
                ingress.continue_resolve(
                    principal=principal.subject,
                    operation=request.operation,
                    account_ref=account_ref,
                    credential_kind=kind,
                    transaction_id=transaction_id,
                    plan_digest=request.plan_digest,
                    expected_generation=request.expected_generation,
                    idempotency_key=apply_key,
                ),
            )
        except SecretIngressOwnerError as error:
            if error.code == "credential.upload_expired":
                return None
            raise _owner_service_error(error) from None
        except BaseException as error:
            owner_error = _owner_service_error(error)
            del error
            raise owner_error from None

    def rollback_secret_upload(self, upload_claim: object) -> None:
        """Release a reservation when body admission failed before mutation."""

        ingress = _required(self._secret_ingress)
        try:
            ingress.rollback_upload(upload_claim)
        except Exception as error:
            owner_error = _owner_service_error(error)
            del error
            raise owner_error from None

    def command(
        self,
        principal: AdminPrincipalV1,
        operation: str,
        arguments: Mapping[str, object],
        *,
        expected_generation: int,
        idempotency_key: str,
        plan_digest: str | None = None,
        ingress_session: object | None = None,
        oauth_code: str | None = None,
    ) -> dict[str, object]:
        """Validate a command through ``AdminRequestV1`` and use ``handle``."""

        _reject_secret_arguments(arguments)
        try:
            request = AdminRequestV1(
                operation,
                arguments,
                expected_generation,
                idempotency_key,
                plan_digest,
            )
        except BaseException:
            raise _service_error("control.request_invalid") from None
        return self.handle(
            principal,
            request,
            ingress_session=ingress_session,
            oauth_code=oauth_code,
        )

    def handle(
        self,
        principal: AdminPrincipalV1,
        request: AdminRequestV1,
        *,
        ingress_session: object | None = None,
        oauth_code: str | None = None,
    ) -> dict[str, object]:
        """Dispatch one already-versioned request without transport logic."""

        if (
            type(principal) is not AdminPrincipalV1
            or type(request) is not AdminRequestV1
        ):
            raise _service_error("control.request_invalid")
        _reject_secret_arguments(request.arguments)
        operation = request.operation
        if operation == "control.operations.list":
            return _public_mapping(
                {
                    "schema_version": 1,
                    "catalog_digest": ADMIN_OPERATION_CATALOG_DIGEST,
                    "operation_count": len(ADMIN_OPERATION_CATALOG),
                    "allowed": [
                        (metadata := ADMIN_OPERATION_METADATA[candidate]).scope
                        is not None
                        and metadata.scope in principal.scopes
                        for candidate in ADMIN_OPERATION_CATALOG
                    ],
                }
            )
        scope = QUERY_SCOPES.get(operation) or COMMAND_SCOPES.get(operation)
        if scope is None:
            raise _service_error("control.request_invalid")
        if scope not in principal.scopes:
            raise _denied("authority.scope_denied")
        replay = self._durable_command_replay(request)
        if replay is not None:
            return replay
        if operation in COMMAND_SCOPES:
            self._assert_command_generation(request)
        if ingress_session is None and operation in _INGRESS_APPLY_KINDS:
            ingress_session = self._continued_secret_apply(principal, request)
            if ingress_session is not None:
                principal = replace(principal, step_up=True)
        if operation in _STEP_UP_OPERATIONS and not principal.step_up:
            raise _denied("authority.step_up_required")
        handler = _QUERY_HANDLERS.get(operation) or _COMMAND_HANDLERS.get(operation)
        if handler is None:
            raise _service_error("control.request_invalid")
        try:
            result = handler(self, principal, request, ingress_session, oauth_code)
        except AdminServiceError:
            raise
        except Exception as error:
            owner_error = _owner_service_error(error)
            del error
        else:
            return _public_mapping(result)
        raise owner_error from None

    def _durable_command_replay(
        self, request: AdminRequestV1
    ) -> dict[str, object] | None:
        if request.operation != "google.inventory.refresh":
            return None
        try:
            plan = self._operation_store.lookup_plan(
                kind="google.inventory.refresh",
                generation=_generation(request),
                key=_idempotency(request),
                steps=("inventory.reload",),
            )
        except Exception as error:
            raise _owner_service_error(error) from None
        if plan is None or plan.operation.state == "planned":
            return None
        return public_admin_result(plan.operation)

    def _assert_command_generation(self, request: AdminRequestV1) -> None:
        expected = _generation(request)
        try:
            metadata = ADMIN_OPERATION_METADATA[request.operation]
            domain = metadata.generation_domain
            if domain in {
                "account_registry.openai",
                "account_registry.google",
            }:
                owner = _required(self._account_registry)
                current = owner.current_generation(domain.rsplit(".", 1)[-1])
            elif domain == "openai" or (
                request.operation == "secret.ingress.create"
                and request.arguments.get("credential_kind") == "openai.auth-json"
            ):
                account_ref = cast(str, request.arguments["account_ref"])
                owner = _required(self._openai_credentials)
                current = owner.account_generation(account_ref)
            elif domain == "google_oauth" or (
                request.operation == "secret.ingress.create"
                and request.arguments.get("credential_kind") != "openai.auth-json"
            ):
                account_ref = cast(str, request.arguments["account_ref"])
                owner = _required(self._google_oauth)
                current = owner.account_generation(account_ref)
            elif domain == "ollama":
                owner = _required(self._ollama_fleet)
                current = owner.ollama_generation()
            elif domain == "host":
                host_ref = cast(str, request.arguments["host_ref"])
                host = next(
                    (item for item in self._host_registry.list() if item.ref == host_ref),
                    None,
                )
                if host is None:
                    raise _service_error("control.host_not_found")
                current = host.generation
            else:
                current = self._google_manager.inventory_generation()
        except AdminServiceError:
            raise
        except Exception as error:
            raise _owner_service_error(error) from None
        if type(current) is not int or current != expected:
            raise _service_error("credential.generation_conflict")

    def _account_add(
        self,
        _principal: AdminPrincipalV1,
        request: AdminRequestV1,
        *_values: object,
    ) -> dict[str, object]:
        owner = _required(self._account_registry)
        provider = request.operation.split(".", 1)[0]
        account_ref = cast(str, request.arguments["account_ref"])
        expected_generation = _generation(request)
        receipt = _exact_mapping(
            owner.add_account(
                provider,
                account_ref,
                cast(str, request.arguments["label"]),
                expected_generation=expected_generation,
                idempotency_key=_idempotency(request),
            ),
            frozenset({"account"}),
        )
        account = _exact_mapping(
            receipt["account"], frozenset({"ref", "generation"})
        )
        generation = account["generation"]
        if (
            account["ref"] != account_ref
            or type(generation) is not int
            or generation != expected_generation + 1
        ):
            raise _service_error("control.response_private")
        return {"account": {"ref": account_ref, "generation": generation}}

    def _account_disable(
        self,
        _principal: AdminPrincipalV1,
        request: AdminRequestV1,
        *_values: object,
    ) -> dict[str, object]:
        owner = _required(self._account_registry)
        return dict(
            owner.disable_account(
                "openai",
                cast(str, request.arguments["account_ref"]),
                expected_generation=_generation(request),
                idempotency_key=_idempotency(request),
            )
        )

    def _hosts_list(self, *_values: object) -> dict[str, object]:
        return {"hosts": [_serialize_host(item) for item in self._host_registry.list()]}

    def _hosts_probe(
        self,
        _principal: AdminPrincipalV1,
        request: AdminRequestV1,
        *_values: object,
    ) -> dict[str, object]:
        operation = _required(self._host_probe).probe(
            cast(str, request.arguments["host_ref"]),
            expected_generation=_generation(request),
            idempotency_key=_idempotency(request),
        )
        return public_admin_result(operation)

    def _openai_accounts_list(self, *_values: object) -> dict[str, object]:
        owner = _required(self._openai_accounts)
        return {
            "accounts": [
                _serialize_openai_account(item) for item in owner.list_accounts()
            ]
        }

    def _google_accounts_list(self, *_values: object) -> dict[str, object]:
        owner = _required(self._account_registry)
        status = self._google_manager.status()
        if type(status) is not GoogleAccountInventoryStatusV1:
            raise _service_error("control.response_private")
        return {
            "registry_generation": owner.current_generation("google"),
            "accounts": [
                _serialize_google_account(self._google_account_summary(item, status))
                for item in self._google_manager.list_accounts()
            ]
        }

    def _google_account_summary(
        self, value: object, status: GoogleAccountInventoryStatusV1
    ) -> GoogleAccountSummaryV1:
        account = _google_inventory_account(value)
        account_ref = cast(str, account["ref"])
        generation = cast(int, account["inventory_generation"])
        oauth_state = "unavailable"
        binding = GoogleOAuthClientBindingV1(
            account_ref,
            generation,
            None,
            GoogleOAuthClientAvailabilityV1.UNAVAILABLE,
        )
        owner = self._google_oauth
        if owner is not None:
            try:
                candidate = owner.default_oauth_client_binding(
                    account_ref, expected_generation=generation
                )
            except GoogleOAuthSessionError:
                pass
            else:
                if (
                    type(candidate) is GoogleOAuthClientBindingV1
                    and candidate.account_ref == account_ref
                    and candidate.inventory_generation == generation
                    and (
                        (
                            candidate.availability
                            is GoogleOAuthClientAvailabilityV1.AVAILABLE
                            and type(candidate.default_oauth_client_ref) is str
                        )
                        or (
                            candidate.availability
                            is not GoogleOAuthClientAvailabilityV1.AVAILABLE
                            and candidate.default_oauth_client_ref is None
                        )
                    )
                ):
                    binding = candidate
            try:
                candidate_state = owner.account_oauth_state(
                    account_ref, expected_generation=generation
                )
            except GoogleOAuthSessionError:
                pass
            else:
                if candidate_state not in _GOOGLE_OAUTH_STATES:
                    raise _service_error("control.response_private")
                oauth_state = candidate_state
        quota_state = "unavailable"
        if self._quota_collector is not None:
            candidate_state = self._quota_collector.quota_state(
                account_ref, expected_generation=generation
            )
            if candidate_state not in _GOOGLE_QUOTA_STATES:
                raise _service_error("control.response_private")
            quota_state = candidate_state
        return GoogleAccountSummaryV1(
            account_ref,
            cast(str | None, account["label"]),
            status.new_work_allowed,
            cast(bool, account["subject_bound"]),
            oauth_state,
            generation,
            quota_state,
            cast(int, account["project_count"]),
            cast(int, account["billing_count"]),
            cast(tuple[str, ...], account["billing_refs"]),
            status.state.value,
            binding.default_oauth_client_ref,
            binding.availability.value,
        )

    def _google_projects_list(
        self,
        _principal: AdminPrincipalV1,
        request: AdminRequestV1,
        *_values: object,
    ) -> dict[str, object]:
        account_ref = cast(str, request.arguments["account_ref"])
        return {
            "projects": [
                _serialize_google_project(item)
                for item in self._google_manager.list_projects(account_ref)
            ]
        }

    def _ollama_models_list(self, *_values: object) -> dict[str, object]:
        models = _required(self._ollama_fleet).ollama_models()
        return {
            "schema_version": 1,
            "model_count": len(models),
            "models": [_serialize_ollama_model(model) for model in models],
        }

    def _ollama_instances_list(self, *_values: object) -> dict[str, object]:
        owner = _required(self._ollama_fleet)
        instances = owner.ollama_instances()
        return {
            "schema_version": 1,
            "generation": owner.ollama_generation(),
            "instance_count": len(instances),
            "instances": [
                _serialize_ollama_instance(instance) for instance in instances
            ],
        }

    def _ollama_instance_plan(
        self,
        _principal: AdminPrincipalV1,
        request: AdminRequestV1,
        *_values: object,
    ) -> dict[str, object]:
        arguments = request.arguments
        instance = OllamaInstanceV1(
            cast(str, arguments["ref"]),
            cast(str, arguments["label"]),
            cast(str, arguments["host_ref"]),
            cast(str, arguments["ollama_executable"]),
            cast(str, arguments["models_directory"]),
            cast(tuple[str, ...], arguments["selected_model_refs"]),
            cast(str, arguments["allowed_cpus"]),
            cast(int, arguments["cpu_quota_percent"]),
            cast(int, arguments["cpu_weight"]),
            "planned",
            "unknown",
        )
        plan = _required(self._ollama_fleet).plan_ollama_instance(
            instance, expected_generation=_generation(request)
        )
        self._ollama_plan_digests[plan.plan_id] = _public_digest(plan.plan_digest)
        return _serialize_ollama_plan(plan)

    def _ollama_instance_apply(
        self,
        _principal: AdminPrincipalV1,
        request: AdminRequestV1,
        *_values: object,
    ) -> dict[str, object]:
        plan_id = cast(str, request.arguments["plan_id"])
        if self._ollama_plan_digests.get(plan_id) != _digest(request):
            raise _service_error("control.plan_stale")
        result = _required(self._ollama_fleet).apply_ollama_instance(
            plan_id, expected_generation=_generation(request)
        )
        return _serialize_ollama_apply(result)

    def _ollama_instance_probe(
        self,
        _principal: AdminPrincipalV1,
        request: AdminRequestV1,
        *_values: object,
    ) -> dict[str, object]:
        status = _required(self._ollama_fleet).probe_ollama_instance(
            cast(str, request.arguments["instance_ref"]),
            expected_generation=_generation(request),
        )
        return _serialize_ollama_readiness(status)

    def _operation_get(
        self,
        _principal: AdminPrincipalV1,
        request: AdminRequestV1,
        *_values: object,
    ) -> dict[str, object]:
        operation_id = cast(str, request.arguments["operation_id"])
        operation = self._operation_store.get(operation_id)
        agent_operation_id = self._operation_store.agent_operation_id(operation_id)
        if agent_operation_id is None:
            return public_operation_status(operation)
        if operation.state not in {"partial", "succeeded", "failed", "blocked"}:
            return public_operation_status(operation)
        if self._agent_operations is None:
            raise _service_error("resource.host_response_invalid")
        try:
            agent_operation = self._agent_operations.get(agent_operation_id)
            if agent_operation.state not in {
                "succeeded",
                "failed",
                "unknown",
                "cancelled",
            }:
                raise _service_error("resource.host_response_invalid")
            result = self._agent_operations.result(agent_operation_id)
            if result is None:
                raise _service_error("resource.host_response_invalid")
            return public_operation_status(
                operation,
                result_kind=agent_result_kind(result.kind, result.action),
                result=result.payload,
            )
        except (AdminContractError, AgentOperationError):
            raise _service_error("resource.host_response_invalid") from None

    def _openai_auth_plan(
        self,
        _principal: AdminPrincipalV1,
        request: AdminRequestV1,
        *_values: object,
    ) -> dict[str, object]:
        owner = _required(self._openai_credentials)
        return _serialize_openai_plan(
            owner.plan_auth_sync(
                cast(str, request.arguments["account_ref"]),
                expected_generation=_generation(request),
                idempotency_key=_idempotency(request),
            )
        )

    def _openai_auth_apply(
        self,
        principal: AdminPrincipalV1,
        request: AdminRequestV1,
        ingress_session: object | None,
        _oauth_code: str | None,
    ) -> dict[str, object]:
        credentials = _required(self._openai_credentials)
        ingress = _required(self._secret_ingress)
        resolution = _reserve_ingress_resolution(
            ingress,
            principal,
            request,
            ingress_session,
            credential_kind="openai.auth-json",
        )
        try:
            plan = credentials.resolve_auth_sync_plan(
                cast(str, request.arguments["account_ref"]),
                expected_generation=_generation(request),
                plan_digest=_digest(request),
            )
            reconciled = credentials.reconcile_auth_sync_plan(plan)
            if reconciled is not None:
                ingress.commit_resolve(resolution)
                return _serialize_openai_receipt(reconciled)
            if resolution.reconcile_only:
                ingress.mark_resolve_unknown(resolution)
                raise _service_error("control.owner_unavailable")
            authorized = credentials.authorize_auth_ingress(plan, resolution.upload)
        except AdminServiceError:
            raise
        except Exception:
            if resolution.reconcile_only:
                ingress.mark_resolve_unknown(resolution)
            else:
                ingress.rollback_resolve(resolution)
            raise
        try:
            result = credentials.apply_auth_sync(plan, authorized)
        except Exception:
            _raise_unknown_outcome(ingress, resolution)
        try:
            ingress.commit_resolve(resolution)
        except Exception:
            _raise_unknown_outcome(ingress, resolution)
        return _serialize_openai_receipt(result)

    def _secret_ingress_create(
        self,
        principal: AdminPrincipalV1,
        request: AdminRequestV1,
        *_values: object,
    ) -> dict[str, object]:
        ingress = _required(self._secret_ingress)
        return _serialize_ingress_session(
            ingress.create_session(
                principal=principal.subject,
                account_ref=request.arguments["account_ref"],
                credential_kind=request.arguments["credential_kind"],
                expected_generation=_generation(request),
                idempotency_key=_idempotency(request),
                plan_digest=_digest(request),
                transaction_id=request.arguments.get("transaction_id"),
            )
        )

    def _google_oauth_begin(
        self,
        _principal: AdminPrincipalV1,
        request: AdminRequestV1,
        *_values: object,
    ) -> dict[str, object]:
        owner = _required(self._google_oauth)
        try:
            profile = GoogleOAuthProfileIdV1(request.arguments["scope_profile"])
        except (TypeError, ValueError):
            raise _service_error("control.request_invalid") from None
        return _serialize_oauth_transaction(
            owner.begin_oauth_transaction(
                cast(str, request.arguments["account_ref"]),
                oauth_client_ref=cast(str, request.arguments["oauth_client_ref"]),
                redirect_uri=cast(str, request.arguments["redirect_uri"]),
                scope_profile=profile,
                expected_generation=_generation(request),
                idempotency_key=_idempotency(request),
                principal=_principal.subject,
            )
        )

    def _google_oauth_complete(
        self,
        principal: AdminPrincipalV1,
        request: AdminRequestV1,
        ingress_session: object | None,
        oauth_code: str | None,
    ) -> dict[str, object]:
        owner = _required(self._google_oauth)
        if oauth_code is not None:
            raise _service_error("control.request_invalid")
        ingress = _required(self._secret_ingress)
        resolution = _reserve_ingress_resolution(
            ingress,
            principal,
            request,
            ingress_session,
            credential_kind="google-oauth-code",
        )
        try:
            if resolution.reconcile_only:
                result = owner.reconcile_oauth_transaction(
                    cast(str, request.arguments["transaction_id"]),
                    account_ref=cast(str, request.arguments["account_ref"]),
                    redirect_uri=cast(str, request.arguments["redirect_uri"]),
                    expected_generation=_generation(request),
                    state=cast(str, request.arguments["state"]),
                )
                ingress.commit_resolve(resolution)
                return _serialize_oauth_receipt(result)
            code, _wipe_after = _oauth_code(resolution.upload)
            result = owner.complete_oauth_transaction(
                cast(str, request.arguments["transaction_id"]),
                code=code,
                account_ref=cast(str, request.arguments["account_ref"]),
                redirect_uri=cast(str, request.arguments["redirect_uri"]),
                expected_generation=_generation(request),
                state=cast(str, request.arguments["state"]),
            )
        except Exception:
            if resolution.reconcile_only:
                ingress.mark_resolve_unknown(resolution)
            else:
                ingress.rollback_resolve(resolution)
            raise
        ingress.commit_resolve(resolution)
        return _serialize_oauth_receipt(result)

    def _google_oauth_client_plan(
        self,
        _principal: AdminPrincipalV1,
        request: AdminRequestV1,
        *_values: object,
    ) -> dict[str, object]:
        owner = _required(self._google_oauth)
        return _serialize_oauth_client_plan(
            owner.plan_oauth_client_import(
                cast(str, request.arguments["account_ref"]),
                expected_generation=_generation(request),
                idempotency_key=_idempotency(request),
            )
        )

    def _google_oauth_client_apply(
        self,
        principal: AdminPrincipalV1,
        request: AdminRequestV1,
        ingress_session: object | None,
        _oauth_code: str | None,
    ) -> dict[str, object]:
        owner = _required(self._google_oauth)
        ingress = _required(self._secret_ingress)
        resolution = _reserve_ingress_resolution(
            ingress,
            principal,
            request,
            ingress_session,
            credential_kind="google.oauth-client",
        )
        try:
            plan = owner.resolve_oauth_client_import_plan(
                cast(str, request.arguments["account_ref"]),
                expected_generation=_generation(request),
                plan_digest=_digest(request),
            )
            if resolution.reconcile_only:
                result = owner.reconcile_oauth_client_import(plan, resolution)
                return _serialize_oauth_client_receipt(result)
        except Exception:
            if resolution.reconcile_only:
                ingress.mark_resolve_unknown(resolution)
            else:
                ingress.rollback_resolve(resolution)
            raise
        try:
            result = owner.apply_oauth_client_import(plan, resolution)
        except Exception:
            _raise_unknown_outcome(ingress, resolution)
        return _serialize_oauth_client_receipt(result)

    def _google_inventory_refresh(
        self,
        _principal: AdminPrincipalV1,
        request: AdminRequestV1,
        *_values: object,
    ) -> dict[str, object]:
        generation = _generation(request)
        operation_plan = self._operation_store.plan(
            kind="google.inventory.refresh",
            generation=generation,
            key=_idempotency(request),
            steps=("inventory.reload",),
        )
        if operation_plan.operation.state != "planned":
            return public_admin_result(operation_plan.operation)
        current_generation = self._google_manager.inventory_generation()
        self._operation_store.begin(
            operation_plan.operation_id,
            current_generation=current_generation,
        )
        try:
            status = self._google_manager.reload(expected_generation=generation)
        except GoogleAccountInventoryError as error:
            if type(error) is not GoogleAccountInventoryError:
                raise
            reason_code = _owner_service_error(error).problem.code
            self._operation_store.record_step(
                operation_plan.operation_id,
                "inventory.reload",
                succeeded=False,
                reason_code=reason_code,
            )
            self._operation_store.finish(
                operation_plan.operation_id,
                state="failed",
                reason_codes=(reason_code,),
            )
            raise
        self._operation_store.record_step(
            operation_plan.operation_id,
            "inventory.reload",
            succeeded=True,
        )
        if type(status.generation) is not int:
            raise _service_error("control.response_private")
        return public_admin_result(
            self._operation_store.finish(
                operation_plan.operation_id,
                state="succeeded",
                resulting_generation=status.generation,
            )
        )

    def _google_provision_plan(
        self,
        _principal: AdminPrincipalV1,
        request: AdminRequestV1,
        *_values: object,
    ) -> dict[str, object]:
        collector = _required(self._quota_collector)
        provisioner = _required(self._google_provisioner)
        account_ref = cast(str, request.arguments["account_ref"])
        generation = _generation(request)
        evidence = collector.collect(account_ref, expected_generation=generation)
        return _serialize_provision_plan(
            provisioner.plan(
                account_ref,
                expected_generation=generation,
                idempotency_key=_idempotency(request),
                quota_evidence=evidence,
            )
        )

    def _google_quota_evidence_sync(
        self,
        _principal: AdminPrincipalV1,
        request: AdminRequestV1,
        *_values: object,
    ) -> dict[str, object]:
        collector = _required(self._quota_collector)
        account_ref = cast(str, request.arguments["account_ref"])
        self._google_manager.get_account(account_ref)
        remaining_value = request.arguments["remaining"]
        if (
            type(remaining_value) is not str
            or re.fullmatch(r"0|[1-9][0-9]{0,5}", remaining_value) is None
        ):
            raise _service_error("control.request_invalid")
        return dict(
            collector.sync(
                account_ref,
                remaining=int(remaining_value),
                observed_at=cast(str, request.arguments["observed_at"]),
                source=cast(str, request.arguments["source"]),
                inventory_fingerprint=cast(
                    str, request.arguments["inventory_fingerprint"]
                ),
                expected_generation=_generation(request),
                idempotency_key=_idempotency(request),
            )
        )

    def _google_provision_apply(
        self,
        _principal: AdminPrincipalV1,
        request: AdminRequestV1,
        *_values: object,
    ) -> dict[str, object]:
        provisioner = _required(self._google_provisioner)
        return _serialize_provision_receipt(
            provisioner.apply(
                cast(str, request.arguments["account_ref"]),
                expected_generation=_generation(request),
                idempotency_key=_idempotency(request),
                plan_digest=_digest(request),
            )
        )

    def _google_billing_plan(
        self,
        _principal: AdminPrincipalV1,
        request: AdminRequestV1,
        *_values: object,
    ) -> dict[str, object]:
        owner = _required(self._google_billing)
        return _serialize_billing_plan(
            owner.plan_billing_binding(
                account_ref=cast(str, request.arguments["account_ref"]),
                project_ref=cast(str, request.arguments["project_ref"]),
                billing_ref=cast(str, request.arguments["billing_ref"]),
                expected_generation=_generation(request),
                idempotency_key=_idempotency(request),
            )
        )

    def _google_billing_apply(
        self,
        _principal: AdminPrincipalV1,
        request: AdminRequestV1,
        *_values: object,
    ) -> dict[str, object]:
        owner = _required(self._google_billing)
        return _serialize_billing_receipt(
            owner.apply_billing_binding(
                cast(str, request.arguments["plan_id"]),
                account_ref=cast(str, request.arguments["account_ref"]),
                project_ref=cast(str, request.arguments["project_ref"]),
                billing_ref=cast(str, request.arguments["billing_ref"]),
                expected_generation=_generation(request),
                confirmed_digest=_digest(request),
                idempotency_key=_idempotency(request),
            )
        )


Handler = Callable[
    [
        MasterjetControlService,
        AdminPrincipalV1,
        AdminRequestV1,
        object | None,
        str | None,
    ],
    dict[str, object],
]

_QUERY_HANDLERS: Mapping[str, Handler] = MappingProxyType(
    {
        "hosts.list": MasterjetControlService._hosts_list,
        "openai.accounts.list": MasterjetControlService._openai_accounts_list,
        "google.accounts.list": MasterjetControlService._google_accounts_list,
        "google.projects.list": MasterjetControlService._google_projects_list,
        "operations.get": MasterjetControlService._operation_get,
        "ollama.models.list": MasterjetControlService._ollama_models_list,
        "ollama.instances.list": MasterjetControlService._ollama_instances_list,
    }
)
_COMMAND_HANDLERS: Mapping[str, Handler] = MappingProxyType(
    {
        "hosts.probe": MasterjetControlService._hosts_probe,
        "openai.accounts.add": MasterjetControlService._account_add,
        "openai.accounts.disable": MasterjetControlService._account_disable,
        "google.accounts.add": MasterjetControlService._account_add,
        "openai.auth.plan": MasterjetControlService._openai_auth_plan,
        "openai.auth.apply": MasterjetControlService._openai_auth_apply,
        "secret.ingress.create": MasterjetControlService._secret_ingress_create,
        "google.oauth.begin": MasterjetControlService._google_oauth_begin,
        "google.oauth.complete": MasterjetControlService._google_oauth_complete,
        "google.oauth-client-import.plan": MasterjetControlService._google_oauth_client_plan,
        "google.oauth-client-import.apply": MasterjetControlService._google_oauth_client_apply,
        "google.inventory.refresh": MasterjetControlService._google_inventory_refresh,
        "google.quota-evidence.sync": MasterjetControlService._google_quota_evidence_sync,
        "google.provision.plan": MasterjetControlService._google_provision_plan,
        "google.provision.apply": MasterjetControlService._google_provision_apply,
        "google.billing.plan": MasterjetControlService._google_billing_plan,
        "google.billing.apply": MasterjetControlService._google_billing_apply,
        "ollama.instance.plan": MasterjetControlService._ollama_instance_plan,
        "ollama.instance.apply": MasterjetControlService._ollama_instance_apply,
        "ollama.instance.probe": MasterjetControlService._ollama_instance_probe,
    }
)


def _required(owner: Any | None) -> Any:
    if owner is None:
        raise _service_error("control.owner_unavailable")
    return owner


def _capability(value: object | None) -> SecretIngressCapabilityV1:
    if type(value) is not SecretIngressCapabilityV1:
        raise _service_error("control.request_invalid")
    return value


def _reserve_ingress_resolution(
    ingress: SecretIngressPort,
    principal: AdminPrincipalV1,
    request: AdminRequestV1,
    ingress_session: object | None,
    *,
    credential_kind: str,
) -> SecretIngressResolutionV1:
    capability = _capability(ingress_session)
    account_ref = cast(str, request.arguments["account_ref"])
    transaction_id = request.arguments.get("transaction_id")
    apply_key = request.idempotency_key
    if request.operation == "google.oauth.complete":
        transaction_id = request.arguments.get("transaction_id")
        apply_key = cast(str, transaction_id)
    if (
        capability.subject != principal.subject
        or capability.account_ref != account_ref
        or capability.operation != request.operation
        or capability.credential_kind != credential_kind
        or capability.transaction_id != transaction_id
        or capability.expected_generation != _generation(request)
        or capability.session_generation != _generation(request)
        or capability.apply_idempotency_key != apply_key
        or (
            request.operation != "google.oauth.complete"
            and capability.plan_digest != _digest(request)
        )
    ):
        raise _service_error("credential.upload_expired")
    claim = ingress.reserve_resolve(
        capability.session_id,
        capability=capability,
        principal=principal.subject,
        operation=request.operation,
        account_ref=account_ref,
        credential_kind=credential_kind,
        transaction_id=transaction_id,
        plan_digest=capability.plan_digest,
        expected_generation=capability.expected_generation,
        create_idempotency_key=capability.create_idempotency_key,
        upload_idempotency_key=capability.upload_idempotency_key,
        idempotency_key=capability.apply_idempotency_key,
        session_generation=capability.session_generation,
        receipt_generation=capability.receipt_generation,
        expires_at=capability.expires_at,
    )
    resolution = ingress.resolve(claim)
    if type(resolution) is not SecretIngressResolutionV1:
        raise _service_error("control.response_private")
    return resolution


def _secret_value(value: object) -> bytes | bytearray | memoryview:
    if type(value) in {bytes, bytearray}:
        if len(value) == 0:  # type: ignore[arg-type]
            raise _service_error("control.request_invalid")
        return cast(bytes | bytearray, value)
    if type(value) is memoryview:
        if (
            value.nbytes == 0
            or value.ndim != 1
            or value.itemsize != 1
            or not value.contiguous
        ):
            raise _service_error("control.request_invalid")
        return value
    raise _service_error("control.request_invalid")


def _oauth_code(value: object) -> tuple[str, bytearray | None]:
    raw: bytes | bytearray | memoryview
    if type(value) is bytearray:
        raw = value
        wipe = value
    elif type(value) is bytes:
        raw = value
        wipe = None
    elif type(value) is memoryview and value.ndim == 1 and value.contiguous:
        raw = value
        wipe = None
    else:
        raise _service_error("control.request_invalid")
    try:
        if not 1 <= len(raw) <= 4096:
            raise ValueError
        if type(raw) is bytearray:
            code = raw.decode("ascii")
        elif type(raw) is bytes:
            code = raw.decode("ascii")
        else:
            # Generic borrowed views have no decoder. This runtime-owned copy is
            # the unavoidable Python text boundary; product ingress is bytearray.
            code = cast(memoryview, raw).tobytes().decode("ascii")
        if any(ord(char) <= 0x20 or ord(char) >= 0x7F for char in code):
            raise ValueError
        return code, wipe
    except (UnicodeError, ValueError):
        raise _service_error("control.request_invalid") from None


def _generation(request: AdminRequestV1) -> int:
    value = request.expected_generation
    if type(value) is not int:
        raise _service_error("control.request_invalid")
    return value


def _idempotency(request: AdminRequestV1) -> str:
    value = request.idempotency_key
    if type(value) is not str:
        raise _service_error("control.request_invalid")
    return value


def _digest(request: AdminRequestV1) -> str:
    value = request.plan_digest
    if type(value) is not str:
        raise _service_error("control.request_invalid")
    return value


def _reject_secret_arguments(value: object) -> None:
    try:
        if isinstance(value, Mapping):
            for key, item in value.items():
                if type(key) is not str or key.casefold() in _FORBIDDEN_ARGUMENT_KEYS:
                    raise _service_error("control.request_invalid")
                _reject_secret_arguments(item)
            return
        if type(value) in {list, tuple}:
            values = cast(list[object] | tuple[object, ...], value)
            for item in values:
                _reject_secret_arguments(item)
            return
        if type(value) in {bytes, bytearray, memoryview}:
            raise _service_error("control.request_invalid")
    except AdminServiceError:
        raise
    except BaseException:
        raise _service_error("control.request_invalid") from None


def _public_mapping(value: object) -> dict[str, object]:
    projected = _public_value(value)
    if type(projected) is not dict:
        raise _service_error("control.response_private")
    return cast(dict[str, object], projected)


def _public_value(value: object, *, field: str | None = None) -> object:
    if value is None or type(value) in {bool, int, float}:
        return value
    if type(value) is str:
        if field == "reason_codes":
            if _CODE.fullmatch(value) is None:
                raise _service_error("control.response_private")
            return value
        if field == "authorization_url":
            return _public_authorization_url(value)
        try:
            text = public_admin_text(value)
        except BaseException:
            raise _service_error("control.response_private")
        if text.startswith(("/", "\\")) or re.match(r"[A-Za-z]:[\\/]", text):
            raise _service_error("control.response_private")
        return text
    if type(value) in {bytes, bytearray, memoryview}:
        raise _service_error("control.response_private")
    if type(value) in {list, tuple}:
        values = cast(list[object] | tuple[object, ...], value)
        return [_public_value(item, field=field) for item in values]
    if type(value) is dict:
        result: dict[str, object] = {}
        items = cast(dict[object, object], value).items()
        for key, item in items:
            if type(key) is not str:
                raise _service_error("control.response_private")
            result[key] = _public_value(item, field=key)
        return result
    raise _service_error("control.response_private")


def _public_authorization_url(value: str) -> str:
    try:
        parsed = urllib.parse.urlsplit(value)
        pairs = urllib.parse.parse_qsl(parsed.query, strict_parsing=True)
        allowed = {
            "access_type",
            "client_id",
            "code_challenge",
            "code_challenge_method",
            "prompt",
            "redirect_uri",
            "response_type",
            "scope",
            "state",
        }
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
            or len(value.encode("utf-8")) > 16_384
            or len(pairs) > len(allowed)
            or any(key not in allowed for key, _item in pairs)
        ):
            raise ValueError
        for key, item in pairs:
            if key == "redirect_uri":
                if not item.startswith(("http://127.0.0.1", "http://localhost")):
                    raise ValueError
            elif key == "scope":
                if any(
                    scope != "openid"
                    and not scope.startswith("https://www.googleapis.com/auth/")
                    for scope in item.split()
                ):
                    raise ValueError
            else:
                public_admin_text(item)
    except BaseException:
        raise _service_error("control.response_private") from None
    return value


def _serialize_host(value: ControlHostV1) -> dict[str, object]:
    if type(value) is not ControlHostV1:
        raise _service_error("control.response_private")
    return dict(value.public_projection())


def _serialize_openai_account(value: OpenAIAccountSummaryV1) -> dict[str, object]:
    if type(value) is not OpenAIAccountSummaryV1:
        raise _service_error("control.response_private")
    return {"ref": value.ref, "generation": value.generation}


def _exact_mapping(value: object, fields: frozenset[str]) -> dict[str, object]:
    try:
        if not isinstance(value, Mapping) or frozenset(value) != fields:
            raise _service_error("control.response_private")
        return {field: value[field] for field in fields}
    except AdminServiceError:
        raise
    except BaseException:
        raise _service_error("control.response_private") from None


def _google_inventory_account(value: object) -> dict[str, object]:
    return _exact_mapping(
        value,
        frozenset(
            {
                "ref",
                "label",
                "subject_bound",
                "inventory_generation",
                "project_count",
                "billing_count",
                "billing_refs",
            }
        ),
    )


def _serialize_google_account(value: GoogleAccountSummaryV1) -> dict[str, object]:
    if type(value) is not GoogleAccountSummaryV1:
        raise _service_error("control.response_private")
    return {
        "ref": value.ref,
        "label": value.label,
        "enabled": value.enabled,
        "subject_bound": value.subject_bound,
        "oauth_state": value.oauth_state,
        "inventory_generation": value.inventory_generation,
        "quota_state": value.quota_state,
        "project_count": value.project_count,
        "billing_count": value.billing_count,
        "billing_refs": list(value.billing_refs),
        "reload_state": value.reload_state,
        "default_oauth_client_ref": value.default_oauth_client_ref,
        "oauth_client_availability": value.oauth_client_availability,
    }


def _serialize_google_project(value: object) -> dict[str, object]:
    return _exact_mapping(
        value,
        frozenset(
            {
                "ref",
                "project_name",
                "key_name",
                "purpose",
                "billing_ref",
                "status",
                "inventory_generation",
            }
        ),
    )


def _serialize_ollama_model(value: OllamaModelV1) -> dict[str, object]:
    if type(value) is not OllamaModelV1:
        raise _service_error("control.response_private")
    return {
        "ref": value.ref,
        "provider_model_id": value.provider_model_id,
        "installed": value.installed,
        "hive_enabled": value.hive_enabled,
        "simple_only": value.simple_only,
        "capabilities": list(value.capabilities),
        "evidence_at_utc": value.evidence_at_utc,
    }


def _serialize_ollama_instance(value: OllamaInstanceV1) -> dict[str, object]:
    if type(value) is not OllamaInstanceV1:
        raise _service_error("control.response_private")
    return {
        "ref": value.ref,
        "label": value.label,
        "host_ref": value.host_ref,
        "selected_model_refs": list(value.selected_model_refs),
        "allowed_cpus": value.allowed_cpus,
        "cpu_quota_percent": value.cpu_quota_percent,
        "cpu_weight": value.cpu_weight,
        "lifecycle_state": value.lifecycle_state,
        "readiness_state": value.readiness_state,
        "path_state": "configured_private",
    }


def _serialize_ollama_plan(value: OllamaFleetPlanV1) -> dict[str, object]:
    if type(value) is not OllamaFleetPlanV1:
        raise _service_error("control.response_private")
    return {
        "plan_id": value.plan_id,
        "plan_digest": _public_digest(value.plan_digest),
        "expected_generation": value.registry_generation,
        "resource_generation": value.resource_generation,
        "instance": _serialize_ollama_instance(value.instance),
    }


def _serialize_ollama_readiness(value: OllamaReadinessStatus) -> dict[str, object]:
    if type(value) is not OllamaReadinessStatus:
        raise _service_error("control.response_private")
    return {
        "ready": value.ready,
        "reason_codes": list(value.reason_codes),
        "process_running": value.process_running,
        "cgroup_member": value.cgroup_member,
        "loopback_endpoint_reachable": value.loopback_endpoint_reachable,
        "available_model_ids": list(value.available_model_ids),
    }


def _serialize_ollama_apply(value: OllamaApplyResultV1) -> dict[str, object]:
    if type(value) is not OllamaApplyResultV1:
        raise _service_error("control.response_private")
    return {
        "generation": value.registry.generation,
        "instance": _serialize_ollama_instance(value.instance),
        "readiness": _serialize_ollama_readiness(value.readiness),
        "hive_lanes": [
            {
                "lane_ref": lane.lane_ref,
                "instance_ref": lane.instance_ref,
                "host_ref": lane.host_ref,
                "model_ref": lane.model_ref,
                "provider_model_id": lane.provider_model_id,
                "task_profile": lane.task_profile,
            }
            for lane in value.hive_lanes
        ],
    }


def _serialize_openai_plan(value: AuthSyncPlanV1) -> dict[str, object]:
    if type(value) is not AuthSyncPlanV1:
        raise _service_error("control.response_private")
    return {
        "account_ref": value.account_ref,
        "expected_generation": value.expected_generation,
        "expires_at": value.expires_at,
        "plan_digest": _public_digest(value.plan_digest),
    }


def _serialize_openai_receipt(value: AuthSyncReceiptV1) -> dict[str, object]:
    if type(value) is not AuthSyncReceiptV1:
        raise _service_error("control.response_private")
    return {
        "account_ref": value.account_ref,
        "generation": value.generation,
        "plan_digest": _public_digest(value.plan_digest),
        "state": value.state,
    }


def _serialize_ingress_session(value: SecretIngressSessionV1) -> dict[str, object]:
    if type(value) is not SecretIngressSessionV1:
        raise _service_error("control.response_private")
    return {
        "id": value.id,
        "account_ref": value.account_ref,
        "state": value.state,
        "plan_digest": _public_digest(value.plan_digest),
        "expected_generation": value.expected_generation,
        "expires_at": value.expires_at,
        "session_generation": value.session_generation,
    }


def _serialize_ingress_upload_receipt(
    value: SecretIngressUploadReceiptV1,
) -> dict[str, object]:
    if type(value) is not SecretIngressUploadReceiptV1:
        raise _service_error("control.response_private")
    return {
        "session_id": value.session_id,
        "account_ref": value.account_ref,
        "state": value.state,
        "generation": value.generation,
    }


def _serialize_oauth_transaction(value: GoogleOAuthTransactionV1) -> dict[str, object]:
    if type(value) is not GoogleOAuthTransactionV1:
        raise _service_error("control.response_private")
    return {
        "id": value.id,
        "account_ref": value.account_ref,
        "authorization_url": value.authorization_url,
        "expires_at": value.expires_at,
        "inventory_generation": value.inventory_generation,
    }


def _serialize_oauth_receipt(value: GoogleOAuthSessionReceipt) -> dict[str, object]:
    if type(value) is not GoogleOAuthSessionReceipt:
        raise _service_error("control.response_private")
    return {
        "account_ref": value.account_ref,
        "subject_bound": value.subject_bound,
        "refresh_token_stored": value.refresh_token_stored,
    }


def _serialize_oauth_client_plan(
    value: GoogleOAuthClientImportPlanV1,
) -> dict[str, object]:
    if type(value) is not GoogleOAuthClientImportPlanV1:
        raise _service_error("control.response_private")
    return {
        "id": value.id,
        "account_ref": value.account_ref,
        "expected_generation": value.expected_generation,
        "expires_at": value.expires_at,
        "plan_digest": _public_digest(value.plan_digest),
    }


def _serialize_oauth_client_receipt(
    value: GoogleOAuthClientImportReceiptV1,
) -> dict[str, object]:
    if type(value) is not GoogleOAuthClientImportReceiptV1:
        raise _service_error("control.response_private")
    return {
        "account_ref": value.account_ref,
        "client_ref": value.client_ref,
        "display_name": value.display_name,
        "inventory_generation": value.inventory_generation,
        "client_digest": _public_digest(value.client_digest),
    }


def _serialize_provision_plan(value: FillToQuotaPlan) -> dict[str, object]:
    if type(value) is not FillToQuotaPlan:
        raise _service_error("control.response_private")
    return {
        "account_ref": value.account_ref,
        "expected_subject_id": value.expected_subject_id,
        "quota_remaining": value.quota_remaining,
        "inventory_generation": value.inventory_generation,
        "inventory_fingerprint": value.inventory_fingerprint,
        "projects": [
            {
                "ref": project.ref,
                "project_name": project.project_name,
                "project_id": project.project_id,
                "expected_project_number": project.expected_project_number,
                "key_display_name": project.key_display_name,
            }
            for project in value.projects
        ],
        "plan_digest": _public_digest(value.fingerprint),
    }


def _serialize_provision_receipt(
    value: ProvisionReceipt | ProvisionPartialReceipt,
) -> dict[str, object]:
    if type(value) is ProvisionReceipt:
        return {"completed": value.completed, "planned": value.planned}
    if type(value) is ProvisionPartialReceipt:
        return {
            "attempted": value.attempted,
            "completed": value.completed,
            "planned": value.planned,
            "failed": value.failed,
            "not_attempted": value.not_attempted,
            "reason_code": value.reason_code,
        }
    raise _service_error("control.response_private")


def _serialize_billing_plan(value: GoogleBillingPlanV1) -> dict[str, object]:
    if type(value) is not GoogleBillingPlanV1:
        raise _service_error("control.response_private")
    return {
        "id": value.id,
        "account_ref": value.account_ref,
        "inventory_generation": value.inventory_generation,
        "snapshot_fingerprint": value.snapshot_fingerprint,
        "project_ref": value.project_ref,
        "billing_ref": value.billing_ref,
        "plan_digest": _public_digest(value.digest),
        "created_at": value.created_at.isoformat().replace("+00:00", "Z"),
        "expires_at": value.expires_at.isoformat().replace("+00:00", "Z"),
    }


def _serialize_billing_receipt(value: GoogleBillingReceiptV1) -> dict[str, object]:
    if type(value) is not GoogleBillingReceiptV1:
        raise _service_error("control.response_private")
    return {
        "plan_id": value.plan_id,
        "state": value.state,
        "attempted": value.attempted,
        "completed": value.completed,
        "failed": value.failed,
        "not_attempted": value.not_attempted,
        "reason_code": value.reason_code,
    }


def _public_digest(value: object) -> str:
    if type(value) is not str:
        raise _service_error("control.response_private")
    if value.startswith("sha256:"):
        candidate = value[7:]
    else:
        candidate = value
    if _HEX_DIGEST.fullmatch(candidate) is None:
        raise _service_error("control.response_private")
    return "sha256:" + candidate


_OWNER_ERROR_PREFIXES: tuple[tuple[type[BaseException], tuple[str, ...]], ...] = (
    (SecretIngressOwnerError, ("control.", "credential.")),
    (AdminOperationError, ("control.",)),
    (HostRegistryError, ("control.",)),
    (OpenAICredentialError, ("control.", "credential.", "oauth.")),
    (GoogleAccountInventoryError, ("credential.",)),
    (GoogleOAuthSessionError, ("control.", "credential.", "oauth.")),
    (GoogleCloudProvisionerError, ("provisioner.", "quota.")),
    (GoogleBillingError, ("billing.",)),
    (FleetConflictError, ("control.", "ollama.")),
)


def _owner_service_error(error: BaseException) -> AdminServiceError:
    prefixes = next(
        (
            allowed
            for error_type, allowed in _OWNER_ERROR_PREFIXES
            if type(error) is error_type
        ),
        None,
    )
    try:
        code = getattr(error, "code", None)
    except BaseException:
        code = None
    if not (
        prefixes is not None
        and type(code) is str
        and _CODE.fullmatch(code) is not None
        and code.startswith(prefixes)
    ):
        code = "control.owner_unavailable"
    partial = False
    if prefixes is not None:
        try:
            partial = getattr(error, "partial", None) is not None
        except BaseException:
            partial = True
    effect = (
        "Action may be partially completed" if partial else "Action outcome is unknown"
    )
    return AdminServiceError(_problem(code, effect=effect))


def _problem(
    code: str,
    *,
    effect: str = "No action was started",
    action: str = "Review access and retry",
    retryable: bool = False,
) -> HiveProblemV1:
    return HiveProblemV1(
        code=code,
        severity="error",
        title="Request failed",
        detail="Request could not be completed",
        effect=effect,
        action=action,
        retryable=retryable,
        retry_after_seconds=None,
        correlation_id="corr-" + uuid.uuid4().hex,
        occurred_at=datetime.now(UTC),
    )


def _service_error(code: str) -> AdminServiceError:
    return AdminServiceError(_problem(code))


def _unknown_outcome_error() -> AdminServiceError:
    return AdminServiceError(
        _problem(
            "control.owner_unavailable",
            effect="Action outcome is unknown",
            action="Retry the identical request to reconcile outcome",
            retryable=True,
        )
    )


def _raise_unknown_outcome(
    ingress: SecretIngressPort, resolution: SecretIngressResolutionV1
) -> Never:
    error = _unknown_outcome_error()
    try:
        ingress.mark_resolve_unknown(resolution)
    except Exception as journal_error:
        raise error from journal_error
    raise error


def _denied(code: str) -> AdminDenied:
    return AdminDenied(_problem(code))
