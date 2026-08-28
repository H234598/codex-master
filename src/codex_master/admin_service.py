"""Transport-independent Masterjet administration service boundary."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime
import re
from types import MappingProxyType
from typing import Any, Protocol, cast
import uuid

from .admin_contracts import (
    AdminPrincipalV1,
    AdminRequestV1,
    HiveProblemV1,
    OperationV1,
    public_admin_result,
)
from .admin_hosts import HostRegistry
from .admin_operations import AdminOperationStore
from .google_account_inventory_manager import GoogleAccountInventoryManager
from .google_billing_service import GoogleBillingService
from .google_cloud_provisioner import (
    FillToQuotaPlan,
    ProvisionPartialReceipt,
    ProvisionReceipt,
)
from .google_oauth_authorization import GoogleOAuthProfileIdV1
from .google_oauth_session import (
    GoogleOAuthClientImportPlanV1,
    GoogleOAuthClientImportReceiptV1,
    GoogleOAuthControlService,
    GoogleOAuthSessionReceipt,
    GoogleOAuthTransactionV1,
)
from .openai_credential_service import (
    AuthSyncPlanV1,
    AuthSyncReceiptV1,
    OpenAICredentialService,
)


QUERY_SCOPES = MappingProxyType(
    {
        "hosts.list": "fleet.host.read",
        "openai.accounts.list": "fleet.read",
        "google.accounts.list": "fleet.read",
        "google.projects.list": "fleet.read",
        "operations.get": "fleet.read",
    }
)

COMMAND_SCOPES = MappingProxyType(
    {
        "openai.auth.plan": "fleet.openai.write",
        "openai.auth.apply": "fleet.secrets.ingress",
        "secret.ingress.create": "fleet.secrets.ingress",
        "google.oauth.begin": "fleet.google.oauth",
        "google.oauth.complete": "fleet.google.oauth",
        "google.oauth-client-import.plan": "fleet.google.oauth",
        "google.oauth-client-import.apply": "fleet.google.oauth",
        "google.inventory.refresh": "fleet.google.oauth",
        "google.provision.plan": "fleet.google.provision",
        "google.provision.apply": "fleet.google.provision",
        "google.billing.plan": "fleet.google.billing.bind",
        "google.billing.apply": "fleet.google.billing.bind",
    }
)

_STEP_UP_OPERATIONS = frozenset(
    {
        "openai.auth.apply",
        "secret.ingress.create",
        "google.oauth.begin",
        "google.oauth.complete",
        "google.oauth-client-import.apply",
        "google.provision.apply",
        "google.billing.apply",
    }
)
_CODE = re.compile(r"[a-z][a-z0-9_.-]{0,127}\Z", re.ASCII)
_HEX_DIGEST = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
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
_FORBIDDEN_RESULT_KEYS = _FORBIDDEN_ARGUMENT_KEYS | frozenset({"backend_account_id"})


class OpenAIAccountsPort(Protocol):
    def list_accounts(self) -> Sequence[object]: ...


class QuotaCollectorPort(Protocol):
    def collect(self, account_ref: str, *, expected_generation: int) -> object: ...


class GoogleProvisionerPort(Protocol):
    def plan(
        self,
        account_ref: str,
        *,
        expected_generation: int,
        idempotency_key: str,
        quota_evidence: object,
    ) -> object: ...

    def apply(
        self,
        account_ref: str,
        *,
        expected_generation: int,
        idempotency_key: str,
        plan_digest: str,
    ) -> object: ...


class SecretIngressPort(Protocol):
    def create_session(self, **values: object) -> object: ...

    def resolve(self, session: object, **values: object) -> tuple[object, object]: ...


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
        openai_accounts: OpenAIAccountsPort | None,
        openai_credentials: OpenAICredentialService | None,
        google_manager: GoogleAccountInventoryManager,
        google_oauth: GoogleOAuthControlService | None,
        quota_collector: QuotaCollectorPort | None,
        google_provisioner: GoogleProvisionerPort | None,
        google_billing: GoogleBillingService | None,
        host_registry: HostRegistry,
        secret_ingress: SecretIngressPort | None,
    ) -> None:
        self._operation_store = operation_store
        self._openai_accounts = openai_accounts
        self._openai_credentials = openai_credentials
        self._google_manager = google_manager
        self._google_oauth = google_oauth
        self._quota_collector = quota_collector
        self._google_provisioner = google_provisioner
        self._google_billing = google_billing
        self._host_registry = host_registry
        self._secret_ingress = secret_ingress

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
        scope = QUERY_SCOPES.get(operation) or COMMAND_SCOPES.get(operation)
        if scope is None:
            raise _service_error("control.request_invalid")
        if scope not in principal.scopes:
            raise _denied("authority.scope_denied")
        if operation in _STEP_UP_OPERATIONS and not principal.step_up:
            raise _denied("authority.step_up_required")
        handler = _QUERY_HANDLERS.get(operation) or _COMMAND_HANDLERS.get(operation)
        if handler is None:
            raise _service_error("control.request_invalid")
        try:
            result = handler(self, principal, request, ingress_session, oauth_code)
        except AdminServiceError:
            raise
        except BaseException as error:
            code = _foreign_error_code(error)
            del error
        else:
            return _public_mapping(result)
        raise _service_error(code) from None

    def _hosts_list(self, *_values: object) -> dict[str, object]:
        return {"hosts": _public_sequence(self._host_registry.list())}

    def _openai_accounts_list(self, *_values: object) -> dict[str, object]:
        owner = _required(self._openai_accounts)
        return {"accounts": _public_sequence(owner.list_accounts())}

    def _google_accounts_list(self, *_values: object) -> dict[str, object]:
        return {"accounts": _public_sequence(self._google_manager.list_accounts())}

    def _google_projects_list(
        self,
        _principal: AdminPrincipalV1,
        request: AdminRequestV1,
        *_values: object,
    ) -> dict[str, object]:
        account_ref = cast(str, request.arguments["account_ref"])
        return {
            "projects": _public_sequence(
                self._google_manager.list_projects(account_ref)
            )
        }

    def _operation_get(
        self,
        _principal: AdminPrincipalV1,
        request: AdminRequestV1,
        *_values: object,
    ) -> dict[str, object]:
        account_ref = cast(str, request.arguments["account_ref"])
        operation_id = cast(str, request.arguments["operation_id"])
        operation = self._operation_store.get(operation_id)
        if not operation.kind.endswith(":" + account_ref):
            raise _denied("authority.scope_denied")
        return public_admin_result(operation)

    def _openai_auth_plan(
        self,
        _principal: AdminPrincipalV1,
        request: AdminRequestV1,
        *_values: object,
    ) -> dict[str, object]:
        owner = _required(self._openai_credentials)
        return _project(
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
        plan, upload = ingress.resolve(
            _capability(ingress_session),
            principal=principal.subject,
            account_ref=request.arguments["account_ref"],
            credential_kind="openai.auth-json",
            expected_generation=_generation(request),
            idempotency_key=_idempotency(request),
            plan_digest=_digest(request),
        )
        return _project(credentials.apply_auth_sync(plan, upload))

    def _secret_ingress_create(
        self,
        principal: AdminPrincipalV1,
        request: AdminRequestV1,
        *_values: object,
    ) -> dict[str, object]:
        ingress = _required(self._secret_ingress)
        return _project(
            ingress.create_session(
                principal=principal.subject,
                account_ref=request.arguments["account_ref"],
                credential_kind=request.arguments["credential_kind"],
                expected_generation=_generation(request),
                idempotency_key=_idempotency(request),
                plan_digest=_digest(request),
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
        return _project(
            owner.begin_oauth_transaction(
                cast(str, request.arguments["account_ref"]),
                oauth_client_ref=cast(str, request.arguments["oauth_client_ref"]),
                redirect_uri=cast(str, request.arguments["redirect_uri"]),
                scope_profile=profile,
                expected_generation=_generation(request),
            )
        )

    def _google_oauth_complete(
        self,
        _principal: AdminPrincipalV1,
        request: AdminRequestV1,
        _ingress_session: object | None,
        oauth_code: str | None,
    ) -> dict[str, object]:
        owner = _required(self._google_oauth)
        if type(oauth_code) is not str or not oauth_code:
            raise _service_error("control.request_invalid")
        return _project(
            owner.complete_oauth_transaction(
                cast(str, request.arguments["transaction_id"]),
                code=oauth_code,
                account_ref=cast(str, request.arguments["account_ref"]),
                redirect_uri=cast(str, request.arguments["redirect_uri"]),
                expected_generation=_generation(request),
                state=cast(str, request.arguments["state"]),
            )
        )

    def _google_oauth_client_plan(
        self,
        _principal: AdminPrincipalV1,
        request: AdminRequestV1,
        *_values: object,
    ) -> dict[str, object]:
        owner = _required(self._google_oauth)
        return _project(
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
        plan, upload = ingress.resolve(
            _capability(ingress_session),
            principal=principal.subject,
            account_ref=request.arguments["account_ref"],
            credential_kind="google.oauth-client",
            expected_generation=_generation(request),
            idempotency_key=_idempotency(request),
            plan_digest=_digest(request),
        )
        return _project(owner.apply_oauth_client_import(plan, upload))

    def _google_inventory_refresh(
        self,
        _principal: AdminPrincipalV1,
        request: AdminRequestV1,
        *_values: object,
    ) -> dict[str, object]:
        self._google_manager.get_account(cast(str, request.arguments["account_ref"]))
        return _project(self._google_manager.reload())

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
        return _project(
            provisioner.plan(
                account_ref,
                expected_generation=generation,
                idempotency_key=_idempotency(request),
                quota_evidence=evidence,
            )
        )

    def _google_provision_apply(
        self,
        _principal: AdminPrincipalV1,
        request: AdminRequestV1,
        *_values: object,
    ) -> dict[str, object]:
        provisioner = _required(self._google_provisioner)
        return _project(
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
        return _project(
            owner.plan_billing_binding(
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
        return _project(
            owner.apply_billing_binding(
                cast(str, request.arguments["plan_id"]),
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
    }
)
_COMMAND_HANDLERS: Mapping[str, Handler] = MappingProxyType(
    {
        "openai.auth.plan": MasterjetControlService._openai_auth_plan,
        "openai.auth.apply": MasterjetControlService._openai_auth_apply,
        "secret.ingress.create": MasterjetControlService._secret_ingress_create,
        "google.oauth.begin": MasterjetControlService._google_oauth_begin,
        "google.oauth.complete": MasterjetControlService._google_oauth_complete,
        "google.oauth-client-import.plan": MasterjetControlService._google_oauth_client_plan,
        "google.oauth-client-import.apply": MasterjetControlService._google_oauth_client_apply,
        "google.inventory.refresh": MasterjetControlService._google_inventory_refresh,
        "google.provision.plan": MasterjetControlService._google_provision_plan,
        "google.provision.apply": MasterjetControlService._google_provision_apply,
        "google.billing.plan": MasterjetControlService._google_billing_plan,
        "google.billing.apply": MasterjetControlService._google_billing_apply,
    }
)


def _required(owner: Any | None) -> Any:
    if owner is None:
        raise _service_error("control.owner_unavailable")
    return owner


def _capability(value: object | None) -> object:
    if value is None or type(value) in {bytes, bytearray, memoryview}:
        raise _service_error("control.request_invalid")
    return value


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


def _public_sequence(value: object) -> list[object]:
    if type(value) not in {list, tuple}:
        raise _service_error("control.response_private")
    values = cast(list[object] | tuple[object, ...], value)
    return [_public_value(item) for item in values]


def _project(value: object) -> dict[str, object]:
    if isinstance(value, OperationV1):
        return public_admin_result(value)
    if isinstance(value, AuthSyncPlanV1):
        return {
            "account_ref": value.account_ref,
            "expected_generation": value.expected_generation,
            "expires_at": value.expires_at,
            "plan_digest": _public_digest(value.plan_digest),
        }
    if isinstance(value, AuthSyncReceiptV1):
        return {
            "account_ref": value.account_ref,
            "generation": value.generation,
            "plan_digest": _public_digest(value.plan_digest),
            "state": value.state,
        }
    if isinstance(value, GoogleOAuthTransactionV1):
        return {
            "id": value.id,
            "account_ref": value.account_ref,
            "authorization_url": value.authorization_url,
            "expires_at": value.expires_at,
            "inventory_generation": value.inventory_generation,
        }
    if isinstance(value, GoogleOAuthSessionReceipt):
        return {
            "account_ref": value.account_ref,
            "subject_bound": value.subject_bound,
            "refresh_token_stored": value.refresh_token_stored,
        }
    if isinstance(value, GoogleOAuthClientImportPlanV1):
        return {
            "id": value.id,
            "account_ref": value.account_ref,
            "expected_generation": value.expected_generation,
            "expires_at": value.expires_at,
            "plan_digest": _public_digest(value.plan_digest),
        }
    if isinstance(value, GoogleOAuthClientImportReceiptV1):
        return {
            "account_ref": value.account_ref,
            "client_ref": value.client_ref,
            "display_name": value.display_name,
            "inventory_generation": value.inventory_generation,
            "client_digest": _public_digest(value.client_digest),
        }
    if isinstance(value, FillToQuotaPlan):
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
            "plan_digest": value.fingerprint,
        }
    if isinstance(value, ProvisionReceipt):
        return {"completed": value.completed, "planned": value.planned}
    if isinstance(value, ProvisionPartialReceipt):
        return {
            "attempted": value.attempted,
            "completed": value.completed,
            "planned": value.planned,
            "failed": value.failed,
            "not_attempted": value.not_attempted,
            "reason_code": value.reason_code,
        }
    try:
        projector = getattr(value, "public_projection")
    except BaseException:
        if isinstance(value, Mapping):
            return _public_mapping(value)
        raise _service_error("control.response_private") from None
    try:
        projected = projector()
    except BaseException:
        raise _service_error("control.response_private") from None
    return _public_mapping(projected)


def _public_value(value: object) -> object:
    if value is None or type(value) in {bool, int, float}:
        return value
    if type(value) is str:
        if value.startswith(("/", "\\")) or re.match(r"[A-Za-z]:[\\/]", value):
            raise _service_error("control.response_private")
        return value
    if type(value) in {bytes, bytearray, memoryview}:
        raise _service_error("control.response_private")
    if type(value) in {list, tuple}:
        values = cast(list[object] | tuple[object, ...], value)
        return [_public_value(item) for item in values]
    if isinstance(value, Mapping):
        result: dict[str, object] = {}
        try:
            items = tuple(value.items())
        except BaseException:
            raise _service_error("control.response_private") from None
        for key, item in items:
            if type(key) is not str or key.casefold() in _FORBIDDEN_RESULT_KEYS:
                raise _service_error("control.response_private")
            result[key] = _public_value(item)
        return result
    if isinstance(value, OperationV1):
        return public_admin_result(value)
    return _project(value)


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


def _foreign_error_code(error: BaseException) -> str:
    try:
        code = getattr(error, "code", None)
    except BaseException:
        return "control.owner_unavailable"
    if type(code) is str and _CODE.fullmatch(code) is not None:
        return code
    return "control.owner_unavailable"


def _problem(code: str) -> HiveProblemV1:
    return HiveProblemV1(
        code=code,
        severity="error",
        title="Request failed",
        detail="Request could not be completed",
        effect="No action was started",
        action="Review access and retry",
        retryable=False,
        retry_after_seconds=None,
        correlation_id="corr-" + uuid.uuid4().hex,
        occurred_at=datetime.now(UTC),
    )


def _service_error(code: str) -> AdminServiceError:
    return AdminServiceError(_problem(code))


def _denied(code: str) -> AdminDenied:
    return AdminDenied(_problem(code))
