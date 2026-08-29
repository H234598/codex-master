import hashlib
import json
import re
from dataclasses import dataclass, fields
from enum import Enum
from typing import Protocol

from codex_master.remote_queen_bootstrap import (
    ManifestGenerationV1,
    RemoteQueenBootstrapError,
)


REMOTE_QUEEN_MCP_SCHEMA = "remote-queen-mcp-v1"
REMOTE_QUEEN_MCP_PLAN_SCHEMA = "remote-queen-mcp-plan-v1"
MCP_SERVER_NAME = "codex-master"
MCP_TRANSPORT = "streamable-http"
MCP_ENDPOINT_PATH = "/mcp"
MCP_STARTUP_TIMEOUT_MS = 10_000
MCP_TOOL_TIMEOUT_MS = 60_000
MCP_MAX_REQUEST_BYTES = 65_536
MCP_MAX_RESPONSE_BYTES = 1_048_576
MCP_CAPABILITY_MAX_TTL_SECONDS = 900

MCP_REPO_ID = "codex-master"
MCP_TOPIC_ID = "g18-vertex-overflow"
MCP_ROLE = "queen"

ADMIN_AUTHORITY_ID = "masterjet-control"
ADMIN_CONTRACT_NAME = "AdminRequestV1"
ADMIN_TRANSPORT = "authenticated-https-admin"


class RemoteMcpStateKindV1(str, Enum):
    ABSENT = "absent"
    OWNED = "owned"
    FOREIGN = "foreign"


class RemoteMcpActionV1(str, Enum):
    CREATE_CONFIGURATION = "create-configuration"
    REPLACE_OWNED_CONFIGURATION = "replace-owned-configuration"


class McpRetryClassV1(str, Enum):
    NEVER = "never"
    PRE_DISPATCH_ONLY = "pre-dispatch-only"
    READ_ONLY_ONCE = "read-only-once"


@dataclass(frozen=True, slots=True)
class CanonicalMcpToolBindingV1:
    tool_name: str
    input_schema_sha256: str
    required_scopes: tuple[str, ...]
    read_only: bool
    retry_class: McpRetryClassV1
    admin_operation: str | None

    def __post_init__(self) -> None:
        _validate_tool(self, check_digest=False)


@dataclass(frozen=True, slots=True)
class CentralAdminAuthorityRefV1:
    authority_id: str
    contract_name: str
    contract_generation: ManifestGenerationV1
    transport: str
    operation_names: tuple[str, ...]
    authority_digest: str

    def __post_init__(self) -> None:
        _validate_authority(self, check_digest=True)


@dataclass(frozen=True, slots=True)
class McpPrincipalBindingV1:
    principal_id: str
    repo_id: str
    topic_id: str
    role: str
    authority_generation: ManifestGenerationV1
    scopes: tuple[str, ...]
    binding_digest: str

    def __post_init__(self) -> None:
        _validate_principal(self, check_digest=True)


@dataclass(frozen=True, slots=True)
class McpCredentialBindingV1:
    ca_bundle_sha256: str
    mtls_identity_sha256: str
    capability_sha256: str
    capability_generation: ManifestGenerationV1
    max_ttl_seconds: int
    binding_digest: str

    def __post_init__(self) -> None:
        _validate_credentials(self, check_digest=True)


@dataclass(frozen=True, slots=True)
class McpGatewayAttestationV1:
    initialize_ok: bool
    tools_list_ok: bool
    request_id_bound: bool
    replay_rejected: bool
    cancellation_supported: bool
    retry_classification_enforced: bool
    request_size_enforced: bool
    response_size_enforced: bool
    revocation_enforced: bool
    redaction_enforced: bool

    def __post_init__(self) -> None:
        _validate_attestation(self)


@dataclass(frozen=True, slots=True)
class RemoteMcpFactV1:
    state: RemoteMcpStateKindV1
    generation: str | None
    owner_principal_id: str | None
    endpoint_url: str | None
    config_manifest_digest: str | None
    catalog_sha256: str | None
    principal_binding_digest: str | None
    credential_binding_digest: str | None
    admin_authority_digest: str | None
    tool_schema_digests: tuple[str, ...]
    attestation: McpGatewayAttestationV1

    def __post_init__(self) -> None:
        _validate_fact(self)


@dataclass(frozen=True, slots=True)
class RemoteQueenMcpManifestV1:
    schema_version: str
    desired_generation: ManifestGenerationV1
    catalog_generation: ManifestGenerationV1
    endpoint_url: str
    server_name: str
    transport: str
    required: bool
    startup_timeout_ms: int
    tool_timeout_ms: int
    max_request_bytes: int
    max_response_bytes: int
    request_id_required: bool
    replay_rejection_required: bool
    cancellation_required: bool
    revocation_required: bool
    redaction_required: bool
    principal: McpPrincipalBindingV1
    credentials: McpCredentialBindingV1
    tools: tuple[CanonicalMcpToolBindingV1, ...]
    admin_authority: CentralAdminAuthorityRefV1
    manifest_digest: str

    def __post_init__(self) -> None:
        _validate_manifest(self, check_digest=True)


@dataclass(frozen=True, slots=True)
class RemoteQueenMcpPlanV1:
    schema_version: str
    manifest: RemoteQueenMcpManifestV1
    before: RemoteMcpFactV1
    before_digest: str
    action: RemoteMcpActionV1 | None
    remove_own_configuration_on_rollback: bool
    plan_digest: str

    def __post_init__(self) -> None:
        _validate_plan(self, check_digest=True)


@dataclass(frozen=True, slots=True)
class ApplyRemoteQueenMcpRequestV1:
    plan: RemoteQueenMcpPlanV1
    expected_plan_digest: str

    def __post_init__(self) -> None:
        _validate_request(self.plan, self.expected_plan_digest)


@dataclass(frozen=True, slots=True)
class RemoteQueenMcpApplyJournalV1:
    before_digest: str
    created_generation: str
    resulting_fact_digest: str

    def __post_init__(self) -> None:
        _validate_journal(self)


@dataclass(frozen=True, slots=True)
class RemoteQueenMcpApplyResultV1:
    changed: bool
    fact: RemoteMcpFactV1
    journal: RemoteQueenMcpApplyJournalV1 | None

    def __post_init__(self) -> None:
        _validate_bool(self.changed)
        _validate_fact(self.fact)
        if self.journal is not None:
            _validate_journal(self.journal)


@dataclass(frozen=True, slots=True)
class VerifyRemoteQueenMcpRequestV1:
    plan: RemoteQueenMcpPlanV1
    expected_plan_digest: str

    def __post_init__(self) -> None:
        _validate_request(self.plan, self.expected_plan_digest)


@dataclass(frozen=True, slots=True)
class RemoteQueenMcpVerifyResultV1:
    verified: bool
    fact: RemoteMcpFactV1

    def __post_init__(self) -> None:
        _validate_bool(self.verified)
        _validate_fact(self.fact)


@dataclass(frozen=True, slots=True)
class RollbackRemoteQueenMcpRequestV1:
    plan: RemoteQueenMcpPlanV1
    expected_plan_digest: str
    journal: RemoteQueenMcpApplyJournalV1 | None

    def __post_init__(self) -> None:
        _validate_request(self.plan, self.expected_plan_digest)
        if self.journal is not None:
            _validate_journal(self.journal)


@dataclass(frozen=True, slots=True)
class RemoteQueenMcpRollbackResultV1:
    changed: bool
    fact: RemoteMcpFactV1

    def __post_init__(self) -> None:
        _validate_bool(self.changed)
        _validate_fact(self.fact)


class RemoteQueenMcpOperations(Protocol):
    def inspect(self, manifest: RemoteQueenMcpManifestV1) -> RemoteMcpFactV1: ...

    def apply_configuration(
        self, plan: RemoteQueenMcpPlanV1
    ) -> RemoteQueenMcpApplyJournalV1: ...

    def rollback_configuration(
        self,
        plan: RemoteQueenMcpPlanV1,
        journal: RemoteQueenMcpApplyJournalV1,
    ) -> None: ...


def canonical_json_bytes(value: object) -> bytes:
    _validate_domain_value(value)
    payload = _canonicalize(value)
    try:
        return json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    except Exception:
        _inconsistent()


def canonical_digest(value: object) -> str:
    _validate_domain_value(value)
    digest_field = _own_digest_field(value)
    payload = _canonicalize(value, omit_field=digest_field)
    return _sha256_canonical(payload)


def build_admin_authority_ref(
    contract_generation: ManifestGenerationV1,
    operation_names: tuple[str, ...],
) -> CentralAdminAuthorityRefV1:
    _validate_generation(contract_generation)
    _validate_sorted_names(operation_names, "operation", allow_empty=False)
    payload = {
        "authority_id": ADMIN_AUTHORITY_ID,
        "contract_name": ADMIN_CONTRACT_NAME,
        "contract_generation": contract_generation,
        "transport": ADMIN_TRANSPORT,
        "operation_names": operation_names,
    }
    digest = _sha256_payload(payload)
    return CentralAdminAuthorityRefV1(
        ADMIN_AUTHORITY_ID,
        ADMIN_CONTRACT_NAME,
        contract_generation,
        ADMIN_TRANSPORT,
        operation_names,
        digest,
    )


def build_mcp_principal_binding(
    principal_id: str,
    authority_generation: ManifestGenerationV1,
    scopes: tuple[str, ...],
) -> McpPrincipalBindingV1:
    _validate_name(principal_id, "id")
    _validate_generation(authority_generation)
    _validate_sorted_names(scopes, "scope", allow_empty=False)
    payload = {
        "principal_id": principal_id,
        "repo_id": MCP_REPO_ID,
        "topic_id": MCP_TOPIC_ID,
        "role": MCP_ROLE,
        "authority_generation": authority_generation,
        "scopes": scopes,
    }
    digest = _sha256_payload(payload)
    return McpPrincipalBindingV1(
        principal_id,
        MCP_REPO_ID,
        MCP_TOPIC_ID,
        MCP_ROLE,
        authority_generation,
        scopes,
        digest,
    )


def build_mcp_credential_binding(
    ca_bundle_sha256: str,
    mtls_identity_sha256: str,
    capability_sha256: str,
    capability_generation: ManifestGenerationV1,
) -> McpCredentialBindingV1:
    _validate_digest(ca_bundle_sha256)
    _validate_digest(mtls_identity_sha256)
    _validate_digest(capability_sha256)
    _validate_generation(capability_generation)
    payload = {
        "ca_bundle_sha256": ca_bundle_sha256,
        "mtls_identity_sha256": mtls_identity_sha256,
        "capability_sha256": capability_sha256,
        "capability_generation": capability_generation,
        "max_ttl_seconds": MCP_CAPABILITY_MAX_TTL_SECONDS,
    }
    digest = _sha256_payload(payload)
    return McpCredentialBindingV1(
        ca_bundle_sha256,
        mtls_identity_sha256,
        capability_sha256,
        capability_generation,
        MCP_CAPABILITY_MAX_TTL_SECONDS,
        digest,
    )


def build_remote_queen_mcp_manifest(
    desired_generation: ManifestGenerationV1,
    catalog_generation: ManifestGenerationV1,
    endpoint_url: str,
    principal: McpPrincipalBindingV1,
    credentials: McpCredentialBindingV1,
    tools: tuple[CanonicalMcpToolBindingV1, ...],
    admin_authority: CentralAdminAuthorityRefV1,
) -> RemoteQueenMcpManifestV1:
    _validate_generation(desired_generation)
    _validate_generation(catalog_generation)
    _validate_endpoint(endpoint_url)
    _validate_manifest_components(principal, credentials, tools, admin_authority)
    payload = _manifest_payload(
        desired_generation,
        catalog_generation,
        endpoint_url,
        principal,
        credentials,
        tools,
        admin_authority,
    )
    digest = _sha256_payload(payload)
    return RemoteQueenMcpManifestV1(
        REMOTE_QUEEN_MCP_SCHEMA,
        desired_generation,
        catalog_generation,
        endpoint_url,
        MCP_SERVER_NAME,
        MCP_TRANSPORT,
        True,
        MCP_STARTUP_TIMEOUT_MS,
        MCP_TOOL_TIMEOUT_MS,
        MCP_MAX_REQUEST_BYTES,
        MCP_MAX_RESPONSE_BYTES,
        True,
        True,
        True,
        True,
        True,
        principal,
        credentials,
        tools,
        admin_authority,
        digest,
    )


def remote_mcp_fact_digest(fact: RemoteMcpFactV1) -> str:
    _validate_fact(fact)
    return canonical_digest(fact)


def plan_remote_queen_mcp(
    manifest: RemoteQueenMcpManifestV1,
    operations: RemoteQueenMcpOperations,
) -> RemoteQueenMcpPlanV1:
    _validate_manifest(manifest, check_digest=True)
    fact = _inspect(manifest, operations, "RQ_E_MCP_UNAVAILABLE")
    try:
        _validate_fact(fact)
    except RemoteQueenBootstrapError:
        _foreign_state()
    desired = _desired_fact(manifest)
    if fact.state is RemoteMcpStateKindV1.FOREIGN:
        _foreign_state()
    if fact.state is RemoteMcpStateKindV1.ABSENT:
        return _make_plan(manifest, fact, RemoteMcpActionV1.CREATE_CONFIGURATION, True)
    if fact.owner_principal_id != manifest.principal.principal_id:
        _foreign_state()
    if _fact_configuration_matches(fact, desired):
        _require_attestation(fact.attestation)
        return _make_plan(manifest, fact, None, False)
    return _make_plan(
        manifest,
        fact,
        RemoteMcpActionV1.REPLACE_OWNED_CONFIGURATION,
        False,
    )


def apply_remote_queen_mcp(
    request: ApplyRemoteQueenMcpRequestV1,
    operations: RemoteQueenMcpOperations,
) -> RemoteQueenMcpApplyResultV1:
    _validate_apply_request(request)
    plan = request.plan
    if plan.action is None:
        return RemoteQueenMcpApplyResultV1(False, plan.before, None)
    current = _inspect(plan.manifest, operations, "RQ_E_MCP_UNAVAILABLE")
    try:
        _validate_fact(current)
    except RemoteQueenBootstrapError:
        _inconsistent()
    if remote_mcp_fact_digest(current) != plan.before_digest:
        _inconsistent()
    try:
        journal = operations.apply_configuration(plan)
    except Exception:
        _unavailable()
    if type(journal) is not RemoteQueenMcpApplyJournalV1:
        _unavailable()
    if (
        journal.before_digest != plan.before_digest
        or journal.created_generation != plan.manifest.desired_generation.generation
    ):
        _unavailable()
    result_fact = _inspect(plan.manifest, operations, "RQ_E_MCP_UNAVAILABLE")
    try:
        _validate_fact(result_fact)
    except RemoteQueenBootstrapError:
        _unavailable()
    _require_desired_fact(result_fact, plan.manifest)
    if journal.resulting_fact_digest != remote_mcp_fact_digest(result_fact):
        _unavailable()
    return RemoteQueenMcpApplyResultV1(True, result_fact, journal)


def verify_remote_queen_mcp(
    request: VerifyRemoteQueenMcpRequestV1,
    operations: RemoteQueenMcpOperations,
) -> RemoteQueenMcpVerifyResultV1:
    _validate_verify_request(request)
    fact = _inspect(request.plan.manifest, operations, "RQ_E_MCP_UNAVAILABLE")
    try:
        _validate_fact(fact)
    except RemoteQueenBootstrapError:
        _unavailable()
    _require_desired_fact(fact, request.plan.manifest)
    return RemoteQueenMcpVerifyResultV1(True, fact)


def rollback_remote_queen_mcp(
    request: RollbackRemoteQueenMcpRequestV1,
    operations: RemoteQueenMcpOperations,
) -> RemoteQueenMcpRollbackResultV1:
    _validate_rollback_request(request)
    plan = request.plan
    if plan.action is None:
        if request.journal is not None:
            _rollback_drift()
        return RemoteQueenMcpRollbackResultV1(False, plan.before)
    journal = request.journal
    if journal is None:
        _rollback_drift()
    if (
        journal.before_digest != plan.before_digest
        or journal.created_generation != plan.manifest.desired_generation.generation
    ):
        _rollback_drift()
    current = _inspect(plan.manifest, operations, "RQ_E_ROLLBACK_DRIFT")
    try:
        _validate_fact(current)
    except RemoteQueenBootstrapError:
        _rollback_drift()
    if (
        not _fact_is_desired(current, plan.manifest)
        or remote_mcp_fact_digest(current) != journal.resulting_fact_digest
    ):
        _rollback_drift()
    try:
        operations.rollback_configuration(plan, journal)
    except Exception:
        _rollback_drift()
    restored = _inspect(plan.manifest, operations, "RQ_E_ROLLBACK_DRIFT")
    try:
        _validate_fact(restored)
    except RemoteQueenBootstrapError:
        _rollback_drift()
    if remote_mcp_fact_digest(restored) != plan.before_digest or restored != plan.before:
        _rollback_drift()
    return RemoteQueenMcpRollbackResultV1(True, restored)


def _inconsistent() -> None:
    raise RemoteQueenBootstrapError("RQ_E_PLAN_INCONSISTENT")


def _foreign_state() -> None:
    raise RemoteQueenBootstrapError("RQ_E_FOREIGN_STATE")


def _unavailable() -> None:
    raise RemoteQueenBootstrapError("RQ_E_MCP_UNAVAILABLE")


def _scope() -> None:
    raise RemoteQueenBootstrapError("RQ_E_MCP_SCOPE")


def _rollback_drift() -> None:
    raise RemoteQueenBootstrapError("RQ_E_ROLLBACK_DRIFT")


def _validate_bool(value: object) -> None:
    if type(value) is not bool:
        _inconsistent()


def _validate_int(value: object) -> None:
    if type(value) is not int:
        _inconsistent()


def _validate_exact_text(value: object, expected: str) -> None:
    if type(value) is not str or value != expected:
        _inconsistent()


def _validate_generation_token(value: object) -> None:
    if type(value) is not str or not value:
        _inconsistent()
    if any(ord(char) < 33 or ord(char) > 126 or char in "/\\" for char in value):
        _inconsistent()


def _validate_generation(value: object) -> None:
    if type(value) is not ManifestGenerationV1:
        _inconsistent()
    _validate_generation_token(value.generation)
    if type(value.sha256) is not str or re.fullmatch(r"[0-9a-f]{64}", value.sha256) is None:
        _inconsistent()


def _validate_name(value: object, kind: str) -> None:
    if type(value) is not str or not value or len(value) > 128:
        _inconsistent()
    if any(ord(char) < 33 or ord(char) > 126 or char in "/\\" for char in value):
        _inconsistent()
    if kind == "tool":
        pattern = r"[A-Za-z0-9](?:[A-Za-z0-9_.-]*[A-Za-z0-9])?"
        separators = "_.-"
    elif kind in {"scope", "operation"}:
        pattern = r"[A-Za-z0-9](?:[A-Za-z0-9_.:-]*[A-Za-z0-9])?"
        separators = "_.:-"
    else:
        pattern = r"[A-Za-z0-9](?:[A-Za-z0-9_.:-]*[A-Za-z0-9])?"
        separators = "_.:-"
    if re.fullmatch(pattern, value) is None:
        _inconsistent()
    if any(first in separators and second in separators for first, second in zip(value, value[1:])):
        _inconsistent()


def _validate_digest(value: object) -> None:
    if type(value) is not str or re.fullmatch(r"sha256:[0-9a-f]{64}", value) is None:
        _inconsistent()


def _validate_sorted_names(
    value: object,
    kind: str,
    *,
    allow_empty: bool,
) -> None:
    if type(value) is not tuple or (not allow_empty and not value) or len(value) > 64:
        _inconsistent()
    for item in value:
        _validate_name(item, kind)
    if len(value) != len(set(value)) or tuple(sorted(value)) != value:
        _inconsistent()


def _validate_digest_tuple(value: object, *, allow_empty: bool) -> None:
    if type(value) is not tuple or (not allow_empty and not value) or len(value) > 64:
        _inconsistent()
    for item in value:
        _validate_digest(item)
    if len(value) != len(set(value)):
        _inconsistent()


def _validate_endpoint(value: object) -> None:
    if type(value) is not str or not value:
        _inconsistent()
    if any(ord(char) < 33 or ord(char) > 126 for char in value):
        _inconsistent()
    if not value.startswith("https://") or not value.endswith(MCP_ENDPOINT_PATH):
        _inconsistent()
    authority = value[len("https://") : -len(MCP_ENDPOINT_PATH)]
    if not authority or "/" in authority or "\\" in authority:
        _inconsistent()
    if any(char in authority for char in "@?#%[]"):
        _inconsistent()
    if ":" in authority:
        if authority.count(":") != 1:
            _inconsistent()
        host, port = authority.split(":")
        if re.fullmatch(r"[0-9]+", port) is None:
            _inconsistent()
        if len(port) > 5:
            _inconsistent()
        port_number = int(port)
        if port_number < 1 or port_number > 65535:
            _inconsistent()
    else:
        host = authority
    if len(host) > 253:
        _inconsistent()
    if host != host.lower():
        _inconsistent()
    if host in {"local", "localhost"} or host.endswith(".local"):
        _inconsistent()
    if re.fullmatch(
        r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*",
        host,
    ) is None:
        _inconsistent()
    labels = host.split(".")
    if len(labels) == 4 and all(label.isdigit() for label in labels):
        _inconsistent()


def _validate_tool(value: CanonicalMcpToolBindingV1, *, check_digest: bool) -> None:
    if type(value) is not CanonicalMcpToolBindingV1:
        _inconsistent()
    _validate_name(value.tool_name, "tool")
    _validate_digest(value.input_schema_sha256)
    _validate_sorted_names(value.required_scopes, "scope", allow_empty=False)
    _validate_bool(value.read_only)
    if type(value.retry_class) is not McpRetryClassV1:
        _inconsistent()
    if value.retry_class is McpRetryClassV1.READ_ONLY_ONCE and not value.read_only:
        _scope()
    if not value.read_only and value.retry_class is not McpRetryClassV1.NEVER:
        _scope()
    if value.admin_operation is not None:
        _validate_name(value.admin_operation, "operation")


def _validate_authority(value: CentralAdminAuthorityRefV1, *, check_digest: bool) -> None:
    if type(value) is not CentralAdminAuthorityRefV1:
        _inconsistent()
    _validate_exact_text(value.authority_id, ADMIN_AUTHORITY_ID)
    _validate_exact_text(value.contract_name, ADMIN_CONTRACT_NAME)
    _validate_exact_text(value.transport, ADMIN_TRANSPORT)
    _validate_generation(value.contract_generation)
    _validate_sorted_names(value.operation_names, "operation", allow_empty=False)
    _validate_digest(value.authority_digest)
    if check_digest and value.authority_digest != _digest_dataclass(value, "authority_digest"):
        _inconsistent()


def _validate_principal(value: McpPrincipalBindingV1, *, check_digest: bool) -> None:
    if type(value) is not McpPrincipalBindingV1:
        _inconsistent()
    _validate_name(value.principal_id, "id")
    _validate_exact_text(value.repo_id, MCP_REPO_ID)
    _validate_exact_text(value.topic_id, MCP_TOPIC_ID)
    _validate_exact_text(value.role, MCP_ROLE)
    _validate_generation(value.authority_generation)
    _validate_sorted_names(value.scopes, "scope", allow_empty=False)
    _validate_digest(value.binding_digest)
    if check_digest and value.binding_digest != _digest_dataclass(value, "binding_digest"):
        _inconsistent()


def _validate_credentials(value: McpCredentialBindingV1, *, check_digest: bool) -> None:
    if type(value) is not McpCredentialBindingV1:
        _inconsistent()
    _validate_digest(value.ca_bundle_sha256)
    _validate_digest(value.mtls_identity_sha256)
    _validate_digest(value.capability_sha256)
    _validate_generation(value.capability_generation)
    _validate_int(value.max_ttl_seconds)
    if value.max_ttl_seconds != MCP_CAPABILITY_MAX_TTL_SECONDS:
        _inconsistent()
    _validate_digest(value.binding_digest)
    if check_digest and value.binding_digest != _digest_dataclass(value, "binding_digest"):
        _inconsistent()


def _validate_attestation(value: McpGatewayAttestationV1) -> None:
    if type(value) is not McpGatewayAttestationV1:
        _inconsistent()
    for field in fields(value):
        _validate_bool(getattr(value, field.name))


def _validate_journal(value: RemoteQueenMcpApplyJournalV1) -> None:
    if type(value) is not RemoteQueenMcpApplyJournalV1:
        _inconsistent()
    _validate_digest(value.before_digest)
    _validate_generation_token(value.created_generation)
    _validate_digest(value.resulting_fact_digest)


def _validate_fact(value: RemoteMcpFactV1) -> None:
    if type(value) is not RemoteMcpFactV1:
        _inconsistent()
    if type(value.state) is not RemoteMcpStateKindV1:
        _inconsistent()
    if value.generation is not None:
        _validate_generation_token(value.generation)
    if value.owner_principal_id is not None:
        _validate_name(value.owner_principal_id, "id")
    if value.endpoint_url is not None:
        _validate_endpoint(value.endpoint_url)
    for item in (
        value.config_manifest_digest,
        value.catalog_sha256,
        value.principal_binding_digest,
        value.credential_binding_digest,
        value.admin_authority_digest,
    ):
        if item is not None:
            _validate_digest(item)
    _validate_digest_tuple(value.tool_schema_digests, allow_empty=value.state is RemoteMcpStateKindV1.ABSENT)
    _validate_attestation(value.attestation)
    optional_values = (
        value.generation,
        value.owner_principal_id,
        value.endpoint_url,
        value.config_manifest_digest,
        value.catalog_sha256,
        value.principal_binding_digest,
        value.credential_binding_digest,
        value.admin_authority_digest,
    )
    if value.state is RemoteMcpStateKindV1.ABSENT:
        if any(item is not None for item in optional_values) or value.tool_schema_digests:
            _foreign_state()
        if any(getattr(value.attestation, field.name) for field in fields(value.attestation)):
            _foreign_state()
    else:
        if any(item is None for item in optional_values) or not value.tool_schema_digests:
            _foreign_state()


def _validate_manifest_components(
    principal: McpPrincipalBindingV1,
    credentials: McpCredentialBindingV1,
    tools: tuple[CanonicalMcpToolBindingV1, ...],
    admin_authority: CentralAdminAuthorityRefV1,
) -> None:
    _validate_principal(principal, check_digest=True)
    _validate_credentials(credentials, check_digest=True)
    _validate_authority(admin_authority, check_digest=True)
    if type(tools) is not tuple or not tools or len(tools) > 64:
        _inconsistent()
    for tool in tools:
        _validate_tool(tool, check_digest=False)
    if len({tool.tool_name for tool in tools}) != len(tools):
        _inconsistent()
    if tuple(tool.tool_name for tool in tools) != tuple(sorted(tool.tool_name for tool in tools)):
        _inconsistent()
    principal_scopes = set(principal.scopes)
    required_scopes = {scope for tool in tools for scope in tool.required_scopes}
    if not required_scopes.issubset(principal_scopes):
        _scope()
    if principal_scopes != required_scopes:
        _scope()
    tool_admin_operations = {
        tool.admin_operation for tool in tools if tool.admin_operation is not None
    }
    authority_operations = set(admin_authority.operation_names)
    if not tool_admin_operations.issubset(authority_operations):
        _scope()
    if tool_admin_operations != authority_operations:
        _scope()


def _manifest_payload(
    desired_generation: ManifestGenerationV1,
    catalog_generation: ManifestGenerationV1,
    endpoint_url: str,
    principal: McpPrincipalBindingV1,
    credentials: McpCredentialBindingV1,
    tools: tuple[CanonicalMcpToolBindingV1, ...],
    admin_authority: CentralAdminAuthorityRefV1,
) -> dict[str, object]:
    return {
        "schema_version": REMOTE_QUEEN_MCP_SCHEMA,
        "desired_generation": desired_generation,
        "catalog_generation": catalog_generation,
        "endpoint_url": endpoint_url,
        "server_name": MCP_SERVER_NAME,
        "transport": MCP_TRANSPORT,
        "required": True,
        "startup_timeout_ms": MCP_STARTUP_TIMEOUT_MS,
        "tool_timeout_ms": MCP_TOOL_TIMEOUT_MS,
        "max_request_bytes": MCP_MAX_REQUEST_BYTES,
        "max_response_bytes": MCP_MAX_RESPONSE_BYTES,
        "request_id_required": True,
        "replay_rejection_required": True,
        "cancellation_required": True,
        "revocation_required": True,
        "redaction_required": True,
        "principal": principal,
        "credentials": credentials,
        "tools": tools,
        "admin_authority": admin_authority,
    }


def _validate_manifest(value: RemoteQueenMcpManifestV1, *, check_digest: bool) -> None:
    if type(value) is not RemoteQueenMcpManifestV1:
        _inconsistent()
    _validate_exact_text(value.schema_version, REMOTE_QUEEN_MCP_SCHEMA)
    _validate_generation(value.desired_generation)
    _validate_generation(value.catalog_generation)
    _validate_endpoint(value.endpoint_url)
    _validate_exact_text(value.server_name, MCP_SERVER_NAME)
    _validate_exact_text(value.transport, MCP_TRANSPORT)
    _validate_bool(value.required)
    if not value.required:
        _inconsistent()
    for actual, expected in (
        (value.startup_timeout_ms, MCP_STARTUP_TIMEOUT_MS),
        (value.tool_timeout_ms, MCP_TOOL_TIMEOUT_MS),
        (value.max_request_bytes, MCP_MAX_REQUEST_BYTES),
        (value.max_response_bytes, MCP_MAX_RESPONSE_BYTES),
    ):
        _validate_int(actual)
        if actual != expected:
            _inconsistent()
    for flag in (
        value.request_id_required,
        value.replay_rejection_required,
        value.cancellation_required,
        value.revocation_required,
        value.redaction_required,
    ):
        _validate_bool(flag)
        if not flag:
            _inconsistent()
    _validate_manifest_components(value.principal, value.credentials, value.tools, value.admin_authority)
    _validate_digest(value.manifest_digest)
    if check_digest and value.manifest_digest != _digest_dataclass(value, "manifest_digest"):
        _inconsistent()


def _validate_plan(value: RemoteQueenMcpPlanV1, *, check_digest: bool) -> None:
    if type(value) is not RemoteQueenMcpPlanV1:
        _inconsistent()
    if value.schema_version != REMOTE_QUEEN_MCP_PLAN_SCHEMA:
        _inconsistent()
    _validate_manifest(value.manifest, check_digest=True)
    _validate_fact(value.before)
    _validate_digest(value.before_digest)
    if value.before_digest != remote_mcp_fact_digest(value.before):
        _inconsistent()
    if value.action is not None and type(value.action) is not RemoteMcpActionV1:
        _inconsistent()
    _validate_bool(value.remove_own_configuration_on_rollback)
    if value.action is None:
        if value.remove_own_configuration_on_rollback or not _fact_is_desired(value.before, value.manifest):
            _inconsistent()
    elif value.action is RemoteMcpActionV1.CREATE_CONFIGURATION:
        if not value.remove_own_configuration_on_rollback or value.before.state is not RemoteMcpStateKindV1.ABSENT:
            _inconsistent()
    elif value.action is RemoteMcpActionV1.REPLACE_OWNED_CONFIGURATION:
        if (
            value.remove_own_configuration_on_rollback
            or value.before.state is not RemoteMcpStateKindV1.OWNED
            or value.before.owner_principal_id != value.manifest.principal.principal_id
        ):
            _inconsistent()
    else:
        _inconsistent()
    _validate_digest(value.plan_digest)
    if check_digest and value.plan_digest != _digest_dataclass(value, "plan_digest"):
        _inconsistent()


def _validate_request(plan: object, expected_plan_digest: object) -> None:
    if type(plan) is not RemoteQueenMcpPlanV1:
        _inconsistent()
    _validate_plan(plan, check_digest=True)
    _validate_digest(expected_plan_digest)
    if expected_plan_digest != plan.plan_digest:
        _inconsistent()


def _validate_apply_request(request: ApplyRemoteQueenMcpRequestV1) -> None:
    if type(request) is not ApplyRemoteQueenMcpRequestV1:
        _inconsistent()
    _validate_request(request.plan, request.expected_plan_digest)


def _validate_verify_request(request: VerifyRemoteQueenMcpRequestV1) -> None:
    if type(request) is not VerifyRemoteQueenMcpRequestV1:
        _inconsistent()
    _validate_request(request.plan, request.expected_plan_digest)


def _validate_rollback_request(request: RollbackRemoteQueenMcpRequestV1) -> None:
    if type(request) is not RollbackRemoteQueenMcpRequestV1:
        _inconsistent()
    _validate_request(request.plan, request.expected_plan_digest)
    if request.journal is not None and type(request.journal) is not RemoteQueenMcpApplyJournalV1:
        _inconsistent()


def _desired_fact(manifest: RemoteQueenMcpManifestV1) -> RemoteMcpFactV1:
    return RemoteMcpFactV1(
        RemoteMcpStateKindV1.OWNED,
        manifest.desired_generation.generation,
        manifest.principal.principal_id,
        manifest.endpoint_url,
        manifest.manifest_digest,
        "sha256:" + manifest.catalog_generation.sha256,
        manifest.principal.binding_digest,
        manifest.credentials.binding_digest,
        manifest.admin_authority.authority_digest,
        tuple(tool.input_schema_sha256 for tool in manifest.tools),
        McpGatewayAttestationV1(True, True, True, True, True, True, True, True, True, True),
    )


def _fact_configuration_matches(fact: RemoteMcpFactV1, desired: RemoteMcpFactV1) -> bool:
    return (
        fact.state is desired.state
        and fact.generation == desired.generation
        and fact.owner_principal_id == desired.owner_principal_id
        and fact.endpoint_url == desired.endpoint_url
        and fact.config_manifest_digest == desired.config_manifest_digest
        and fact.catalog_sha256 == desired.catalog_sha256
        and fact.principal_binding_digest == desired.principal_binding_digest
        and fact.credential_binding_digest == desired.credential_binding_digest
        and fact.admin_authority_digest == desired.admin_authority_digest
        and fact.tool_schema_digests == desired.tool_schema_digests
    )


def _fact_is_desired(fact: RemoteMcpFactV1, manifest: RemoteQueenMcpManifestV1) -> bool:
    desired = _desired_fact(manifest)
    return _fact_configuration_matches(fact, desired) and fact.attestation == desired.attestation


def _require_attestation(attestation: McpGatewayAttestationV1) -> None:
    unavailable_fields = (
        "initialize_ok",
        "tools_list_ok",
        "request_id_bound",
        "cancellation_supported",
        "request_size_enforced",
        "response_size_enforced",
        "redaction_enforced",
    )
    if any(not getattr(attestation, field) for field in unavailable_fields):
        _unavailable()
    scoped_fields = ("replay_rejected", "retry_classification_enforced", "revocation_enforced")
    if any(not getattr(attestation, field) for field in scoped_fields):
        _scope()


def _require_desired_fact(fact: RemoteMcpFactV1, manifest: RemoteQueenMcpManifestV1) -> None:
    desired = _desired_fact(manifest)
    if not _fact_configuration_matches(fact, desired):
        _unavailable()
    _require_attestation(fact.attestation)
    if fact != desired:
        _unavailable()


def _make_plan(
    manifest: RemoteQueenMcpManifestV1,
    before: RemoteMcpFactV1,
    action: RemoteMcpActionV1 | None,
    remove: bool,
) -> RemoteQueenMcpPlanV1:
    before_digest = remote_mcp_fact_digest(before)
    payload = {
        "schema_version": REMOTE_QUEEN_MCP_PLAN_SCHEMA,
        "manifest": manifest,
        "before": before,
        "before_digest": before_digest,
        "action": action,
        "remove_own_configuration_on_rollback": remove,
    }
    plan_digest = _sha256_payload(payload)
    return RemoteQueenMcpPlanV1(
        REMOTE_QUEEN_MCP_PLAN_SCHEMA,
        manifest,
        before,
        before_digest,
        action,
        remove,
        plan_digest,
    )


def _inspect(
    manifest: RemoteQueenMcpManifestV1,
    operations: RemoteQueenMcpOperations,
    error_code: str,
) -> RemoteMcpFactV1:
    try:
        return operations.inspect(manifest)
    except Exception:
        raise RemoteQueenBootstrapError(error_code)


def _own_digest_field(value: object) -> str | None:
    if type(value) is McpPrincipalBindingV1:
        return "binding_digest"
    if type(value) is McpCredentialBindingV1:
        return "binding_digest"
    if type(value) is CentralAdminAuthorityRefV1:
        return "authority_digest"
    if type(value) is RemoteQueenMcpManifestV1:
        return "manifest_digest"
    if type(value) is RemoteQueenMcpPlanV1:
        return "plan_digest"
    return None


def _digest_dataclass(value: object, digest_field: str) -> str:
    return _sha256_canonical(_canonicalize(value, omit_field=digest_field))


def _sha256_payload(value: object) -> str:
    _validate_domain_value(value)
    return _sha256_canonical(_canonicalize(value))


def _sha256_canonical(value: object) -> str:
    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    except Exception:
        _inconsistent()
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _canonicalize(value: object, *, omit_field: str | None = None) -> object:
    if value is None or type(value) is bool or type(value) is int or type(value) is float or type(value) is str:
        return value
    if type(value) in (
        RemoteMcpStateKindV1,
        RemoteMcpActionV1,
        McpRetryClassV1,
    ):
        return value.value
    if type(value) is tuple:
        return [_canonicalize(item) for item in value]
    if type(value) is dict:
        return {key: _canonicalize(item) for key, item in value.items()}
    if type(value) in (
        ManifestGenerationV1,
        CanonicalMcpToolBindingV1,
        CentralAdminAuthorityRefV1,
        McpPrincipalBindingV1,
        McpCredentialBindingV1,
        McpGatewayAttestationV1,
        RemoteMcpFactV1,
        RemoteQueenMcpManifestV1,
        RemoteQueenMcpPlanV1,
        ApplyRemoteQueenMcpRequestV1,
        RemoteQueenMcpApplyJournalV1,
        RemoteQueenMcpApplyResultV1,
        VerifyRemoteQueenMcpRequestV1,
        RemoteQueenMcpVerifyResultV1,
        RollbackRemoteQueenMcpRequestV1,
        RemoteQueenMcpRollbackResultV1,
    ):
        payload = {}
        for field in fields(value):
            if omit_field is not None and field.name == omit_field:
                continue
            payload[field.name] = _canonicalize(getattr(value, field.name))
        return payload
    _inconsistent()


def _validate_domain_value(value: object) -> None:
    if value is None or type(value) is bool or type(value) is int or type(value) is str:
        return
    if type(value) is float:
        if value != value or value in (float("inf"), float("-inf")):
            _inconsistent()
        return
    if type(value) in (RemoteMcpStateKindV1, RemoteMcpActionV1, McpRetryClassV1):
        return
    if type(value) is tuple:
        for item in value:
            _validate_domain_value(item)
        return
    if type(value) is dict:
        for key, item in value.items():
            if type(key) is not str:
                _inconsistent()
            _validate_domain_value(item)
        return
    if type(value) is ManifestGenerationV1:
        _validate_generation(value)
        return
    if type(value) is CanonicalMcpToolBindingV1:
        _validate_tool(value, check_digest=False)
        return
    if type(value) is CentralAdminAuthorityRefV1:
        _validate_authority(value, check_digest=True)
        return
    if type(value) is McpPrincipalBindingV1:
        _validate_principal(value, check_digest=True)
        return
    if type(value) is McpCredentialBindingV1:
        _validate_credentials(value, check_digest=True)
        return
    if type(value) is McpGatewayAttestationV1:
        _validate_attestation(value)
        return
    if type(value) is RemoteMcpFactV1:
        _validate_fact(value)
        return
    if type(value) is RemoteQueenMcpManifestV1:
        _validate_manifest(value, check_digest=True)
        return
    if type(value) is RemoteQueenMcpPlanV1:
        _validate_plan(value, check_digest=True)
        return
    if type(value) is ApplyRemoteQueenMcpRequestV1:
        _validate_request(value.plan, value.expected_plan_digest)
        return
    if type(value) is RemoteQueenMcpApplyJournalV1:
        _validate_journal(value)
        return
    if type(value) is RemoteQueenMcpApplyResultV1:
        _validate_bool(value.changed)
        _validate_fact(value.fact)
        if value.journal is not None:
            _validate_domain_value(value.journal)
        return
    if type(value) is VerifyRemoteQueenMcpRequestV1:
        _validate_request(value.plan, value.expected_plan_digest)
        return
    if type(value) is RemoteQueenMcpVerifyResultV1:
        _validate_bool(value.verified)
        _validate_fact(value.fact)
        return
    if type(value) is RollbackRemoteQueenMcpRequestV1:
        _validate_request(value.plan, value.expected_plan_digest)
        if value.journal is not None:
            _validate_domain_value(value.journal)
        return
    if type(value) is RemoteQueenMcpRollbackResultV1:
        _validate_bool(value.changed)
        _validate_fact(value.fact)
        return
    _inconsistent()
