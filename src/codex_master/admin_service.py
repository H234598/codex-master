"""Transport-independent Masterjet administration service boundary."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
import re
from types import MappingProxyType
from typing import Any, Protocol, cast
import urllib.parse
import uuid

from .admin_contracts import (
    AdminPrincipalV1,
    AdminRequestV1,
    HiveProblemV1,
    public_admin_result,
    public_admin_text,
)
from .admin_hosts import ControlHostV1, HostRegistry, HostRegistryError
from .admin_operations import AdminOperationError, AdminOperationStore
from .google_account_inventory import GoogleAccountInventoryError
from .google_account_inventory_manager import GoogleAccountInventoryManager
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
        "google.inventory.refresh": "fleet.google.inventory.refresh",
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


class OpenAIAccountsPort(Protocol):
    def list_accounts(self) -> Sequence[OpenAIAccountSummaryV1]: ...


class QuotaCollectorPort(Protocol):
    def collect(self, account_ref: str, *, expected_generation: int) -> object: ...


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


class SecretIngressPort(Protocol):
    def create_session(self, **values: object) -> SecretIngressSessionV1: ...

    def resolve(self, session: object, **values: object) -> tuple[object, object]: ...


@dataclass(frozen=True, slots=True)
class OpenAIAccountSummaryV1:
    ref: str
    generation: int


@dataclass(frozen=True, slots=True)
class SecretIngressSessionV1:
    id: str
    account_ref: str
    state: str


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
            owner_error = _owner_service_error(error)
            del error
        else:
            return _public_mapping(result)
        raise owner_error from None

    def _hosts_list(self, *_values: object) -> dict[str, object]:
        return {"hosts": [_serialize_host(item) for item in self._host_registry.list()]}

    def _openai_accounts_list(self, *_values: object) -> dict[str, object]:
        owner = _required(self._openai_accounts)
        return {
            "accounts": [
                _serialize_openai_account(item) for item in owner.list_accounts()
            ]
        }

    def _google_accounts_list(self, *_values: object) -> dict[str, object]:
        return {
            "accounts": [
                _serialize_google_account(item)
                for item in self._google_manager.list_accounts()
            ]
        }

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
        plan, upload = ingress.resolve(
            _capability(ingress_session),
            principal=principal.subject,
            account_ref=request.arguments["account_ref"],
            credential_kind="openai.auth-json",
            expected_generation=_generation(request),
            idempotency_key=_idempotency(request),
            plan_digest=_digest(request),
        )
        return _serialize_openai_receipt(credentials.apply_auth_sync(plan, upload))

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
        _principal: AdminPrincipalV1,
        request: AdminRequestV1,
        _ingress_session: object | None,
        oauth_code: str | None,
    ) -> dict[str, object]:
        owner = _required(self._google_oauth)
        if type(oauth_code) is not str or not oauth_code:
            raise _service_error("control.request_invalid")
        return _serialize_oauth_receipt(
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
        plan, upload = ingress.resolve(
            _capability(ingress_session),
            principal=principal.subject,
            account_ref=request.arguments["account_ref"],
            credential_kind="google.oauth-client",
            expected_generation=_generation(request),
            idempotency_key=_idempotency(request),
            plan_digest=_digest(request),
        )
        return _serialize_oauth_client_receipt(
            owner.apply_oauth_client_import(plan, upload)
        )

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
        status = self._google_manager.reload(expected_generation=generation)
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


def _public_value(value: object, *, field: str | None = None) -> object:
    if value is None or type(value) in {bool, int, float}:
        return value
    if type(value) is str:
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
        return [_public_value(item) for item in values]
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


def _serialize_google_account(value: object) -> dict[str, object]:
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
            }
        ),
    )


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
    return {"id": value.id, "account_ref": value.account_ref, "state": value.state}


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
    (AdminOperationError, ("control.",)),
    (HostRegistryError, ("control.",)),
    (OpenAICredentialError, ("control.", "credential.", "oauth.")),
    (GoogleAccountInventoryError, ("credential.",)),
    (GoogleOAuthSessionError, ("control.", "credential.", "oauth.")),
    (GoogleCloudProvisionerError, ("provisioner.", "quota.")),
    (GoogleBillingError, ("billing.",)),
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


def _problem(code: str, *, effect: str = "No action was started") -> HiveProblemV1:
    return HiveProblemV1(
        code=code,
        severity="error",
        title="Request failed",
        detail="Request could not be completed",
        effect=effect,
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
