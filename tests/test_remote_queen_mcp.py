import ast
import inspect
from dataclasses import FrozenInstanceError, fields, replace
import pytest

from codex_master.remote_queen_bootstrap import (
    ManifestGenerationV1,
    RemoteQueenBootstrapError,
)
from codex_master.remote_queen_mcp import (
    ADMIN_AUTHORITY_ID,
    ADMIN_CONTRACT_NAME,
    ADMIN_TRANSPORT,
    MCP_CAPABILITY_MAX_TTL_SECONDS,
    MCP_ENDPOINT_PATH,
    MCP_MAX_REQUEST_BYTES,
    MCP_MAX_RESPONSE_BYTES,
    MCP_REPO_ID,
    MCP_ROLE,
    MCP_SERVER_NAME,
    MCP_STARTUP_TIMEOUT_MS,
    MCP_TOPIC_ID,
    MCP_TOOL_TIMEOUT_MS,
    MCP_TRANSPORT,
    REMOTE_QUEEN_MCP_PLAN_SCHEMA,
    REMOTE_QUEEN_MCP_SCHEMA,
    ApplyRemoteQueenMcpRequestV1,
    CanonicalMcpToolBindingV1,
    CentralAdminAuthorityRefV1,
    McpCredentialBindingV1,
    McpGatewayAttestationV1,
    McpPrincipalBindingV1,
    McpRetryClassV1,
    RemoteMcpActionV1,
    RemoteMcpFactV1,
    RemoteMcpStateKindV1,
    RemoteQueenMcpApplyJournalV1,
    RemoteQueenMcpApplyResultV1,
    RemoteQueenMcpManifestV1,
    RemoteQueenMcpPlanV1,
    RemoteQueenMcpRollbackResultV1,
    RemoteQueenMcpVerifyResultV1,
    RollbackRemoteQueenMcpRequestV1,
    VerifyRemoteQueenMcpRequestV1,
    apply_remote_queen_mcp,
    build_admin_authority_ref,
    build_mcp_credential_binding,
    build_mcp_principal_binding,
    build_remote_queen_mcp_manifest,
    canonical_digest,
    canonical_json_bytes,
    plan_remote_queen_mcp,
    remote_mcp_fact_digest,
    rollback_remote_queen_mcp,
    verify_remote_queen_mcp,
)


def _generation(prefix: str, letter: str) -> ManifestGenerationV1:
    return ManifestGenerationV1(prefix, letter * 64)


def _vector():
    desired_generation = _generation("rq-mcp-2026-08-29", "a")
    catalog_generation = _generation("mcp-catalog-2026-08-29", "b")
    principal_authority = _generation("queen-authority-2026-08-29", "c")
    admin_contract_generation = _generation("admin-control-2026-08-29", "d")
    capability_generation = _generation("mcp-capability-2026-08-29", "2")
    principal = build_mcp_principal_binding(
        "queen-g18",
        principal_authority,
        ("admin.hosts.read", "fleet.read"),
    )
    credentials = build_mcp_credential_binding(
        "sha256:" + "e" * 64,
        "sha256:" + "f" * 64,
        "sha256:" + "1" * 64,
        capability_generation,
    )
    authority = build_admin_authority_ref(
        admin_contract_generation,
        ("hosts.list",),
    )
    tools = (
        CanonicalMcpToolBindingV1(
            "admin_hosts_list",
            "sha256:" + "4" * 64,
            ("admin.hosts.read",),
            True,
            McpRetryClassV1.READ_ONLY_ONCE,
            "hosts.list",
        ),
        CanonicalMcpToolBindingV1(
            "agent_status",
            "sha256:" + "3" * 64,
            ("fleet.read",),
            True,
            McpRetryClassV1.READ_ONLY_ONCE,
            None,
        ),
    )
    manifest = build_remote_queen_mcp_manifest(
        desired_generation,
        catalog_generation,
        "https://masterjet.example.test/mcp",
        principal,
        credentials,
        tools,
        authority,
    )
    before = RemoteMcpFactV1(
        RemoteMcpStateKindV1.ABSENT,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        (),
        McpGatewayAttestationV1(False, False, False, False, False, False, False, False, False, False),
    )
    plan = plan_remote_queen_mcp(manifest, StaticOperations(before))
    return {
        "desired_generation": desired_generation,
        "catalog_generation": catalog_generation,
        "principal": principal,
        "credentials": credentials,
        "authority": authority,
        "tools": tools,
        "manifest": manifest,
        "before": before,
        "plan": plan,
    }


def _desired_fact(data, *, attestation=None, **changes):
    manifest = data["manifest"]
    if attestation is None:
        attestation = McpGatewayAttestationV1(True, True, True, True, True, True, True, True, True, True)
    fact = RemoteMcpFactV1(
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
        attestation,
    )
    return replace(fact, **changes) if changes else fact


class StaticOperations:
    def __init__(self, fact, *, apply_fact=None, rollback_fact=None, error=None):
        self.fact = fact
        self.apply_fact = apply_fact
        self.rollback_fact = rollback_fact
        self.error = error
        self.calls = []

    def inspect(self, manifest):
        self.calls.append(("inspect", manifest.manifest_digest))
        if self.error is not None:
            raise self.error
        return self.fact

    def apply_configuration(self, plan):
        self.calls.append(("apply_configuration", plan.plan_digest))
        if self.error is not None:
            raise self.error
        before_digest = remote_mcp_fact_digest(plan.before)
        self.fact = self.apply_fact
        return RemoteQueenMcpApplyJournalV1(
            before_digest,
            plan.manifest.desired_generation.generation,
            remote_mcp_fact_digest(self.fact),
        )

    def rollback_configuration(self, plan, journal):
        self.calls.append(("rollback_configuration", journal.resulting_fact_digest))
        if self.error is not None:
            raise self.error
        self.fact = self.rollback_fact


def _error_code(callable_, *args, **kwargs):
    with pytest.raises(RemoteQueenBootstrapError) as caught:
        callable_(*args, **kwargs)
    return caught.value.code


def test_closed_contract_types_constants_and_enum_values_are_immutable():
    assert REMOTE_QUEEN_MCP_SCHEMA == "remote-queen-mcp-v1"
    assert REMOTE_QUEEN_MCP_PLAN_SCHEMA == "remote-queen-mcp-plan-v1"
    assert MCP_SERVER_NAME == "codex-master"
    assert MCP_TRANSPORT == "streamable-http"
    assert MCP_ENDPOINT_PATH == "/mcp"
    assert MCP_STARTUP_TIMEOUT_MS == 10_000
    assert MCP_TOOL_TIMEOUT_MS == 60_000
    assert MCP_MAX_REQUEST_BYTES == 65_536
    assert MCP_MAX_RESPONSE_BYTES == 1_048_576
    assert MCP_CAPABILITY_MAX_TTL_SECONDS == 900
    assert MCP_REPO_ID == "codex-master"
    assert MCP_TOPIC_ID == "g18-vertex-overflow"
    assert MCP_ROLE == "queen"
    assert ADMIN_AUTHORITY_ID == "masterjet-control"
    assert ADMIN_CONTRACT_NAME == "AdminRequestV1"
    assert ADMIN_TRANSPORT == "authenticated-https-admin"
    assert [item.value for item in RemoteMcpStateKindV1] == ["absent", "owned", "foreign"]
    assert [item.value for item in RemoteMcpActionV1] == [
        "create-configuration",
        "replace-owned-configuration",
    ]
    assert [item.value for item in McpRetryClassV1] == [
        "never",
        "pre-dispatch-only",
        "read-only-once",
    ]
    expected_fields = {
        CanonicalMcpToolBindingV1: ["tool_name", "input_schema_sha256", "required_scopes", "read_only", "retry_class", "admin_operation"],
        CentralAdminAuthorityRefV1: ["authority_id", "contract_name", "contract_generation", "transport", "operation_names", "authority_digest"],
        McpPrincipalBindingV1: ["principal_id", "repo_id", "topic_id", "role", "authority_generation", "scopes", "binding_digest"],
        McpCredentialBindingV1: ["ca_bundle_sha256", "mtls_identity_sha256", "capability_sha256", "capability_generation", "max_ttl_seconds", "binding_digest"],
        McpGatewayAttestationV1: ["initialize_ok", "tools_list_ok", "request_id_bound", "replay_rejected", "cancellation_supported", "retry_classification_enforced", "request_size_enforced", "response_size_enforced", "revocation_enforced", "redaction_enforced"],
        RemoteMcpFactV1: ["state", "generation", "owner_principal_id", "endpoint_url", "config_manifest_digest", "catalog_sha256", "principal_binding_digest", "credential_binding_digest", "admin_authority_digest", "tool_schema_digests", "attestation"],
        RemoteQueenMcpManifestV1: ["schema_version", "desired_generation", "catalog_generation", "endpoint_url", "server_name", "transport", "required", "startup_timeout_ms", "tool_timeout_ms", "max_request_bytes", "max_response_bytes", "request_id_required", "replay_rejection_required", "cancellation_required", "revocation_required", "redaction_required", "principal", "credentials", "tools", "admin_authority", "manifest_digest"],
        RemoteQueenMcpPlanV1: ["schema_version", "manifest", "before", "before_digest", "action", "remove_own_configuration_on_rollback", "plan_digest"],
        ApplyRemoteQueenMcpRequestV1: ["plan", "expected_plan_digest"],
        RemoteQueenMcpApplyJournalV1: ["before_digest", "created_generation", "resulting_fact_digest"],
        RemoteQueenMcpApplyResultV1: ["changed", "fact", "journal"],
        VerifyRemoteQueenMcpRequestV1: ["plan", "expected_plan_digest"],
        RemoteQueenMcpVerifyResultV1: ["verified", "fact"],
        RollbackRemoteQueenMcpRequestV1: ["plan", "expected_plan_digest", "journal"],
        RemoteQueenMcpRollbackResultV1: ["changed", "fact"],
    }
    for cls, names in expected_fields.items():
        assert [field.name for field in fields(cls)] == names
        assert hasattr(cls, "__slots__")
    data = _vector()
    with pytest.raises(FrozenInstanceError):
        data["manifest"].endpoint_url = "https://other.example.test/mcp"
    assert _error_code(
        McpCredentialBindingV1,
        "sha256:" + "e" * 64,
        "sha256:" + "f" * 64,
        "sha256:" + "1" * 64,
        data["desired_generation"],
        True,
        data["credentials"].binding_digest,
    ) == "RQ_E_PLAN_INCONSISTENT"
    assert _error_code(
        McpGatewayAttestationV1,
        1,
        True,
        True,
        True,
        True,
        True,
        True,
        True,
        True,
        True,
    ) == "RQ_E_PLAN_INCONSISTENT"


def test_every_public_builder_and_operation_function_is_exercised_by_vector():
    data = _vector()
    assert data["principal"].binding_digest.startswith("sha256:")
    assert data["authority"].authority_digest.startswith("sha256:")
    assert data["credentials"].binding_digest.startswith("sha256:")
    assert data["manifest"].manifest_digest.startswith("sha256:")
    assert remote_mcp_fact_digest(data["before"]).startswith("sha256:")
    assert data["plan"].plan_digest.startswith("sha256:")
    operations = StaticOperations(data["before"], apply_fact=_desired_fact(data))
    request = ApplyRemoteQueenMcpRequestV1(data["plan"], data["plan"].plan_digest)
    assert isinstance(apply_remote_queen_mcp(request, operations), RemoteQueenMcpApplyResultV1)
    verify_request = VerifyRemoteQueenMcpRequestV1(data["plan"], data["plan"].plan_digest)
    verify_operations = StaticOperations(data["before"])
    assert _error_code(verify_remote_queen_mcp, verify_request, verify_operations) == "RQ_E_MCP_UNAVAILABLE"
    rollback_request = RollbackRemoteQueenMcpRequestV1(data["plan"], data["plan"].plan_digest, None)
    rollback_operations = StaticOperations(data["before"])
    assert _error_code(rollback_remote_queen_mcp, rollback_request, rollback_operations) == "RQ_E_ROLLBACK_DRIFT"


def test_canonical_digest_vector_matches_literal_attested_values():
    data = _vector()
    assert data["principal"].binding_digest == "sha256:e8b8b123952d2c340153a8ac72dcf309dfb6ac4b1137f18949d010c861c33472"
    assert data["authority"].authority_digest == "sha256:eeebf3870c30f76ad08b9d23ea33eec84b4702d2108322dcfe9839b0b5139ca0"
    assert data["credentials"].binding_digest == "sha256:c8efc1ea986cf0ce0365c696ee9c8cd5ce504a321a10d26ad4cda871854e0b23"
    assert data["manifest"].manifest_digest == "sha256:2df182841ca009004d0e9bb5b83ce70d413e967066843aeabc23bc0a27b81398"
    assert remote_mcp_fact_digest(data["before"]) == "sha256:4de4c445c13b21d4285e2ae6f9250b04dd967b492e4e415b5d6446df131f15f9"
    assert data["plan"].before_digest == "sha256:4de4c445c13b21d4285e2ae6f9250b04dd967b492e4e415b5d6446df131f15f9"
    assert data["plan"].plan_digest == "sha256:b115f1fec98cd54e936384774100986896fa50518c86f7af4d5f83f79fbbe3f1"
    assert canonical_json_bytes({"z": "ä", "a": (True, None, 4)}) == '{"a":[true,null,4],"z":"ä"}'.encode("utf-8")
    assert canonical_digest(("remote", 4)) == "sha256:c1b7c32f0ac50a65ad1df9821f1801852a5c9da3f1a42990c52dc51a2eb1471f"


def test_digest_changes_for_security_fields_and_sorted_equivalents_remain_equal():
    data = _vector()
    same_principal = build_mcp_principal_binding(
        "queen-g18",
        data["principal"].authority_generation,
        ("admin.hosts.read", "fleet.read"),
    )
    assert same_principal.binding_digest == data["principal"].binding_digest
    changed_principal = build_mcp_principal_binding(
        "queen-g19",
        data["principal"].authority_generation,
        ("admin.hosts.read", "fleet.read"),
    )
    assert changed_principal.binding_digest != data["principal"].binding_digest
    changed_credentials = build_mcp_credential_binding(
        data["credentials"].ca_bundle_sha256,
        data["credentials"].mtls_identity_sha256,
        "sha256:" + "2" * 64,
        data["credentials"].capability_generation,
    )
    assert changed_credentials.binding_digest != data["credentials"].binding_digest
    changed_manifest = build_remote_queen_mcp_manifest(
        data["manifest"].desired_generation,
        data["manifest"].catalog_generation,
        "https://other.example.test:443/mcp",
        data["manifest"].principal,
        data["manifest"].credentials,
        data["manifest"].tools,
        data["manifest"].admin_authority,
    )
    assert changed_manifest.manifest_digest != data["manifest"].manifest_digest
    assert _error_code(replace, data["principal"], scopes=("fleet.read",), binding_digest=data["principal"].binding_digest) == "RQ_E_PLAN_INCONSISTENT"
    assert _error_code(
        canonical_json_bytes,
        {1: "non-string-key"},
    ) == "RQ_E_PLAN_INCONSISTENT"
    assert _error_code(canonical_json_bytes, ["lists-not-tuples"]) == "RQ_E_PLAN_INCONSISTENT"
    assert _error_code(canonical_json_bytes, b"bytes") == "RQ_E_PLAN_INCONSISTENT"
    assert _error_code(canonical_json_bytes, float("nan")) == "RQ_E_PLAN_INCONSISTENT"
    assert _error_code(canonical_json_bytes, float("inf")) == "RQ_E_PLAN_INCONSISTENT"


@pytest.mark.parametrize(
    "endpoint",
    [
        "https://masterjet.example.test/mcp",
        "https://masterjet.example.test:1/mcp",
        "https://masterjet.example.test:65535/mcp",
        "https://a-b.c3.example.test:8443/mcp",
        "https://0x7f.example.test/mcp",
        "https://2130706433.example.test/mcp",
    ],
)
def test_endpoint_parser_accepts_only_valid_https_dns_mcp_endpoints(endpoint):
    data = _vector()
    manifest = build_remote_queen_mcp_manifest(
        data["manifest"].desired_generation,
        data["manifest"].catalog_generation,
        endpoint,
        data["manifest"].principal,
        data["manifest"].credentials,
        data["manifest"].tools,
        data["manifest"].admin_authority,
    )
    assert manifest.endpoint_url == endpoint


@pytest.mark.parametrize(
    "endpoint",
    [
        "http://masterjet.example.test/mcp",
        "https://user:pass@masterjet.example.test/mcp",
        "https://masterjet.example.test/mcp?x=1",
        "https://masterjet.example.test/mcp#fragment",
        "https://127.0.0.1/mcp",
        "https://[2001:db8::1]/mcp",
        "https://localhost/mcp",
        "https://masterjet.local/mcp",
        "https://Masterjet.example.test/mcp",
        "https://masterjet..example.test/mcp",
        "https://masterjet.example.test/mcp/",
        "https://masterjet.example.test/other",
        "https://masterjet.example.test/%6dcp",
        "https://masterjet.example.test\\mcp",
        "https://masterjet.example.test/mcp\n",
        "https://masterjet.example.test/mcp\x00",
        "https://münich.example.test/mcp",
        "https://masterjet.example.test:0/mcp",
        "https://masterjet.example.test:65536/mcp",
        "https://masterjet.example.test:/mcp",
    ],
)
def test_endpoint_parser_rejects_transport_path_and_secret_tricks(endpoint):
    data = _vector()
    assert _error_code(
        build_remote_queen_mcp_manifest,
        data["manifest"].desired_generation,
        data["manifest"].catalog_generation,
        endpoint,
        data["manifest"].principal,
        data["manifest"].credentials,
        data["manifest"].tools,
        data["manifest"].admin_authority,
    ) == "RQ_E_PLAN_INCONSISTENT"


@pytest.mark.parametrize(
    "host",
    [
        "2130706433",
        "127",
        "127.1",
        "127.0.1",
        "127.0.0.1",
        "0x7f000001",
        "017700000001",
        "0x7f.1",
        "0177.0.0.1",
        "0x7f.0.01",
    ],
)
def test_endpoint_parser_rejects_legacy_numeric_ipv4_literals(host):
    data = _vector()

    assert _error_code(
        build_remote_queen_mcp_manifest,
        data["manifest"].desired_generation,
        data["manifest"].catalog_generation,
        f"https://{host}/mcp",
        data["manifest"].principal,
        data["manifest"].credentials,
        data["manifest"].tools,
        data["manifest"].admin_authority,
    ) == "RQ_E_PLAN_INCONSISTENT"


def test_secret_canaries_are_rejected_without_entering_repr_json_errors_or_digest():
    canary = "CANARY_PRIVATE_KEY_BEARER_COOKIE_HTTP_BODY"
    generation = _generation("capability", "2")
    with pytest.raises(RemoteQueenBootstrapError) as caught:
        build_mcp_credential_binding(canary, "sha256:" + "f" * 64, "sha256:" + "1" * 64, generation)
    assert canary not in repr(caught.value)
    assert canary not in str(caught.value)
    assert canary not in canonical_json_bytes({"redacted": "sha256:" + "a" * 64}).decode()
    assert canary not in canonical_digest(("redacted", "sha256:" + "a" * 64))


@pytest.mark.parametrize(
    "key",
    [
        "token",
        "SeCrEt",
        "PASSWORD",
        "CoOkIe",
        "CrEdEnTiAl",
        "AuTh",
        "AUTHORIZATION",
        "BeArEr",
        "BeArEr_ToKeN",
        "PrIvAtE-KeY",
        "HtTp_BoDy",
        "ReQuEsT-BoDy",
        "AccessToken",
        "AuthHeader",
        "BearerToken",
        "ClientSecret",
        "PrivateKey",
        "HttpBody",
        "RequestBody",
        "SetCookie",
    ],
)
def test_canonical_json_rejects_casefolded_secret_keys_without_canary_leak(key):
    canary = "CANARY_SECRET_AUTH_BODY_VALUE"

    with pytest.raises(RemoteQueenBootstrapError) as caught:
        canonical_json_bytes({key: canary})

    assert caught.value.code == "RQ_E_PLAN_INCONSISTENT"
    assert canary not in str(caught.value)
    assert canary not in repr(caught.value)


def test_canonical_json_rejects_nested_mixed_case_private_key_canary():
    canary = "CANARY_NESTED_PRIVATE_KEY_VALUE"

    with pytest.raises(RemoteQueenBootstrapError) as caught:
        canonical_json_bytes({"safe": ({"PrIvAtE_KeY": canary},)})

    assert caught.value.code == "RQ_E_PLAN_INCONSISTENT"
    assert canary not in str(caught.value)
    assert canary not in repr(caught.value)


def test_catalog_scope_retry_and_admin_authority_rules_fail_closed():
    data = _vector()
    unsorted_tools = tuple(reversed(data["tools"]))
    assert _error_code(
        build_remote_queen_mcp_manifest,
        data["manifest"].desired_generation,
        data["manifest"].catalog_generation,
        data["manifest"].endpoint_url,
        data["manifest"].principal,
        data["manifest"].credentials,
        unsorted_tools,
        data["manifest"].admin_authority,
    ) == "RQ_E_PLAN_INCONSISTENT"
    narrow_principal = build_mcp_principal_binding(
        "queen-g18",
        data["principal"].authority_generation,
        ("fleet.read",),
    )
    assert _error_code(
        build_remote_queen_mcp_manifest,
        data["manifest"].desired_generation,
        data["manifest"].catalog_generation,
        data["manifest"].endpoint_url,
        narrow_principal,
        data["manifest"].credentials,
        data["manifest"].tools,
        data["manifest"].admin_authority,
    ) == "RQ_E_MCP_SCOPE"
    assert _error_code(
        CanonicalMcpToolBindingV1,
        "write_tool",
        "sha256:" + "5" * 64,
        ("fleet.read",),
        False,
        McpRetryClassV1.READ_ONLY_ONCE,
        None,
    ) == "RQ_E_MCP_SCOPE"
    assert _error_code(
        CanonicalMcpToolBindingV1,
        "write_tool",
        "sha256:" + "5" * 64,
        ("fleet.read",),
        False,
        McpRetryClassV1.PRE_DISPATCH_ONLY,
        None,
    ) == "RQ_E_MCP_SCOPE"
    missing_admin = build_admin_authority_ref(data["authority"].contract_generation, ("other.operation",))
    assert _error_code(
        build_remote_queen_mcp_manifest,
        data["manifest"].desired_generation,
        data["manifest"].catalog_generation,
        data["manifest"].endpoint_url,
        data["principal"],
        data["credentials"],
        data["tools"],
        missing_admin,
    ) == "RQ_E_MCP_SCOPE"
    assert "arguments" not in CanonicalMcpToolBindingV1.__dataclass_fields__
    assert "expected_generation" not in CanonicalMcpToolBindingV1.__dataclass_fields__
    assert "idempotency_key" not in CanonicalMcpToolBindingV1.__dataclass_fields__
    assert "plan_digest" not in CanonicalMcpToolBindingV1.__dataclass_fields__


def test_catalog_rejects_duplicate_admin_operation_across_tool_aliases():
    data = _vector()
    alias = CanonicalMcpToolBindingV1(
        "admin_hosts_alias",
        "sha256:" + "5" * 64,
        ("admin.hosts.read",),
        True,
        McpRetryClassV1.READ_ONLY_ONCE,
        "hosts.list",
    )

    assert _error_code(
        build_remote_queen_mcp_manifest,
        data["manifest"].desired_generation,
        data["manifest"].catalog_generation,
        data["manifest"].endpoint_url,
        data["principal"],
        data["credentials"],
        (alias, *data["tools"]),
        data["authority"],
    ) == "RQ_E_MCP_SCOPE"


def test_plan_matrix_absent_noop_and_owned_stale_are_deterministic():
    data = _vector()
    absent_ops = StaticOperations(data["before"])
    plan = plan_remote_queen_mcp(data["manifest"], absent_ops)
    assert plan.action is RemoteMcpActionV1.CREATE_CONFIGURATION
    assert plan.remove_own_configuration_on_rollback is True
    assert absent_ops.calls == [("inspect", data["manifest"].manifest_digest)]
    desired = _desired_fact(data)
    owned_ops = StaticOperations(desired)
    noop = plan_remote_queen_mcp(data["manifest"], owned_ops)
    assert noop.action is None
    assert noop.remove_own_configuration_on_rollback is False
    assert owned_ops.calls == [("inspect", data["manifest"].manifest_digest)]
    stale = replace(desired, generation="old-generation")
    stale_ops = StaticOperations(stale)
    replace_plan = plan_remote_queen_mcp(data["manifest"], stale_ops)
    assert replace_plan.action is RemoteMcpActionV1.REPLACE_OWNED_CONFIGURATION
    assert replace_plan.remove_own_configuration_on_rollback is False


@pytest.mark.parametrize(
    "changes",
    [
        {"config_manifest_digest": "sha256:" + "5" * 64},
        {"catalog_sha256": "sha256:" + "6" * 64},
        {"tool_schema_digests": ("sha256:" + "7" * 64, "sha256:" + "3" * 64)},
        {"principal_binding_digest": "sha256:" + "8" * 64},
        {"credential_binding_digest": "sha256:" + "9" * 64},
        {"admin_authority_digest": "sha256:" + "0" * 64},
    ],
)
def test_plan_rejects_same_generation_configuration_digest_drift(changes):
    data = _vector()
    operations = StaticOperations(_desired_fact(data, **changes))

    assert _error_code(plan_remote_queen_mcp, data["manifest"], operations) == "RQ_E_MCP_UNAVAILABLE"
    assert operations.calls == [("inspect", data["manifest"].manifest_digest)]


def test_plan_rejects_foreign_malformed_and_contradictory_facts_before_mutation():
    data = _vector()
    desired = _desired_fact(data)
    foreign = replace(desired, state=RemoteMcpStateKindV1.FOREIGN, owner_principal_id="other-queen")
    assert _error_code(plan_remote_queen_mcp, data["manifest"], StaticOperations(foreign)) == "RQ_E_FOREIGN_STATE"
    malformed = object.__new__(RemoteMcpFactV1)
    object.__setattr__(malformed, "state", RemoteMcpStateKindV1.OWNED)
    object.__setattr__(malformed, "generation", None)
    object.__setattr__(malformed, "owner_principal_id", None)
    object.__setattr__(malformed, "endpoint_url", None)
    object.__setattr__(malformed, "config_manifest_digest", None)
    object.__setattr__(malformed, "catalog_sha256", None)
    object.__setattr__(malformed, "principal_binding_digest", None)
    object.__setattr__(malformed, "credential_binding_digest", None)
    object.__setattr__(malformed, "admin_authority_digest", None)
    object.__setattr__(malformed, "tool_schema_digests", ())
    object.__setattr__(malformed, "attestation", desired.attestation)
    assert _error_code(plan_remote_queen_mcp, data["manifest"], StaticOperations(malformed)) == "RQ_E_FOREIGN_STATE"
    contradictory = object.__new__(RemoteMcpFactV1)
    for field in fields(RemoteMcpFactV1):
        object.__setattr__(contradictory, field.name, getattr(desired, field.name))
    object.__setattr__(contradictory, "state", RemoteMcpStateKindV1.ABSENT)
    assert _error_code(plan_remote_queen_mcp, data["manifest"], StaticOperations(contradictory)) == "RQ_E_FOREIGN_STATE"


@pytest.mark.parametrize(
    "field, expected",
    [
        ("initialize_ok", "RQ_E_MCP_UNAVAILABLE"),
        ("tools_list_ok", "RQ_E_MCP_UNAVAILABLE"),
        ("request_id_bound", "RQ_E_MCP_UNAVAILABLE"),
        ("cancellation_supported", "RQ_E_MCP_UNAVAILABLE"),
        ("request_size_enforced", "RQ_E_MCP_UNAVAILABLE"),
        ("response_size_enforced", "RQ_E_MCP_UNAVAILABLE"),
        ("redaction_enforced", "RQ_E_MCP_UNAVAILABLE"),
        ("replay_rejected", "RQ_E_MCP_SCOPE"),
        ("retry_classification_enforced", "RQ_E_MCP_SCOPE"),
        ("revocation_enforced", "RQ_E_MCP_SCOPE"),
    ],
)
def test_plan_requires_each_gateway_attestation(field, expected):
    data = _vector()
    attestation = replace(_desired_fact(data).attestation, **{field: False})
    fact = _desired_fact(data, attestation=attestation)
    assert _error_code(plan_remote_queen_mcp, data["manifest"], StaticOperations(fact)) == expected


def test_port_exception_is_redacted_and_plan_does_not_mutate():
    data = _vector()
    secret = "BEARER PRIVATE KEY stdout stderr"
    operations = StaticOperations(data["before"], error=RuntimeError(secret))
    with pytest.raises(RemoteQueenBootstrapError) as caught:
        plan_remote_queen_mcp(data["manifest"], operations)
    assert caught.value.code == "RQ_E_MCP_UNAVAILABLE"
    assert secret not in str(caught.value)
    assert operations.calls == [("inspect", data["manifest"].manifest_digest)]


def test_apply_noop_has_zero_port_calls_and_action_has_exact_inspect_apply_inspect_order():
    data = _vector()
    desired = _desired_fact(data)
    noop_plan = plan_remote_queen_mcp(data["manifest"], StaticOperations(desired))
    noop_ops = StaticOperations(desired)
    noop_result = apply_remote_queen_mcp(
        ApplyRemoteQueenMcpRequestV1(noop_plan, noop_plan.plan_digest),
        noop_ops,
    )
    assert noop_result == RemoteQueenMcpApplyResultV1(False, desired, None)
    assert noop_ops.calls == []
    action_plan = data["plan"]
    action_ops = StaticOperations(data["before"], apply_fact=desired)
    result = apply_remote_queen_mcp(
        ApplyRemoteQueenMcpRequestV1(action_plan, action_plan.plan_digest),
        action_ops,
    )
    assert result.changed is True
    assert result.fact == desired
    assert result.journal == RemoteQueenMcpApplyJournalV1(
        action_plan.before_digest,
        action_plan.manifest.desired_generation.generation,
        remote_mcp_fact_digest(desired),
    )
    assert action_ops.calls == [
        ("inspect", action_plan.manifest.manifest_digest),
        ("apply_configuration", action_plan.plan_digest),
        ("inspect", action_plan.manifest.manifest_digest),
    ]


def test_apply_rejects_stale_plan_and_bad_journal_without_second_mutation():
    data = _vector()
    desired = _desired_fact(data)
    stale_ops = StaticOperations(desired, apply_fact=desired)
    assert _error_code(
        apply_remote_queen_mcp,
        ApplyRemoteQueenMcpRequestV1(data["plan"], data["plan"].plan_digest),
        stale_ops,
    ) == "RQ_E_PLAN_INCONSISTENT"
    assert stale_ops.calls == [("inspect", data["manifest"].manifest_digest)]
    assert _error_code(
        ApplyRemoteQueenMcpRequestV1,
        data["plan"],
        "sha256:" + "9" * 64,
    ) == "RQ_E_PLAN_INCONSISTENT"


def test_verify_has_one_inspect_no_mutation_and_requires_desired_owned_state():
    data = _vector()
    desired = _desired_fact(data)
    operations = StaticOperations(desired)
    result = verify_remote_queen_mcp(
        VerifyRemoteQueenMcpRequestV1(data["plan"], data["plan"].plan_digest),
        operations,
    )
    assert result == RemoteQueenMcpVerifyResultV1(True, desired)
    assert operations.calls == [("inspect", data["manifest"].manifest_digest)]
    unavailable = StaticOperations(data["before"])
    assert _error_code(
        verify_remote_queen_mcp,
        VerifyRemoteQueenMcpRequestV1(data["plan"], data["plan"].plan_digest),
        unavailable,
    ) == "RQ_E_MCP_UNAVAILABLE"
    assert unavailable.calls == [("inspect", data["manifest"].manifest_digest)]


def test_rollback_noop_has_zero_calls_and_action_restores_bound_before_exactly_once():
    data = _vector()
    desired = _desired_fact(data)
    noop_plan = plan_remote_queen_mcp(data["manifest"], StaticOperations(desired))
    noop_ops = StaticOperations(desired)
    noop_result = rollback_remote_queen_mcp(
        RollbackRemoteQueenMcpRequestV1(noop_plan, noop_plan.plan_digest, None),
        noop_ops,
    )
    assert noop_result == RemoteQueenMcpRollbackResultV1(False, desired)
    assert noop_ops.calls == []
    action_plan = data["plan"]
    journal = RemoteQueenMcpApplyJournalV1(
        action_plan.before_digest,
        action_plan.manifest.desired_generation.generation,
        remote_mcp_fact_digest(desired),
    )
    action_ops = StaticOperations(desired, rollback_fact=data["before"])
    result = rollback_remote_queen_mcp(
        RollbackRemoteQueenMcpRequestV1(action_plan, action_plan.plan_digest, journal),
        action_ops,
    )
    assert result == RemoteQueenMcpRollbackResultV1(True, data["before"])
    assert action_ops.calls == [
        ("inspect", action_plan.manifest.manifest_digest),
        ("rollback_configuration", journal.resulting_fact_digest),
        ("inspect", action_plan.manifest.manifest_digest),
    ]


def test_rollback_rejects_stale_generation_owner_result_digest_and_post_drift_before_mutation():
    data = _vector()
    desired = _desired_fact(data)
    plan = data["plan"]
    good_journal = RemoteQueenMcpApplyJournalV1(
        plan.before_digest,
        plan.manifest.desired_generation.generation,
        remote_mcp_fact_digest(desired),
    )
    for journal in (
        replace(good_journal, before_digest="sha256:" + "9" * 64),
        replace(good_journal, created_generation="old-generation"),
        replace(good_journal, resulting_fact_digest="sha256:" + "9" * 64),
    ):
        operations = StaticOperations(desired, rollback_fact=data["before"])
        assert _error_code(
            rollback_remote_queen_mcp,
            RollbackRemoteQueenMcpRequestV1(plan, plan.plan_digest, journal),
            operations,
        ) == "RQ_E_ROLLBACK_DRIFT"
        expected_calls = (
            []
            if journal.before_digest != plan.before_digest
            or journal.created_generation != plan.manifest.desired_generation.generation
            else [("inspect", plan.manifest.manifest_digest)]
        )
        assert operations.calls == expected_calls
    foreign = replace(desired, owner_principal_id="other-queen")
    operations = StaticOperations(foreign, rollback_fact=data["before"])
    assert _error_code(
        rollback_remote_queen_mcp,
        RollbackRemoteQueenMcpRequestV1(plan, plan.plan_digest, good_journal),
        operations,
    ) == "RQ_E_ROLLBACK_DRIFT"
    assert operations.calls == [("inspect", plan.manifest.manifest_digest)]


def test_ast_effect_gate_rejects_forbidden_imports_calls_and_admin_envelope_usage():
    import codex_master.remote_queen_mcp as module

    tree = ast.parse(inspect.getsource(module))
    allowed_modules = {
        "dataclasses",
        "enum",
        "hashlib",
        "json",
        "re",
        "typing",
        "codex_master.remote_queen_bootstrap",
    }
    forbidden_modules = {
        "os",
        "pathlib",
        "subprocess",
        "socket",
        "ssl",
        "http",
        "urllib",
        "asyncio",
        "threading",
        "multiprocessing",
        "shutil",
        "tempfile",
        "requests",
        "httpx",
        "paramiko",
        "fabric",
        "anyio",
        "trio",
        "codex_master.server",
        "codex_master.admin_",
        "codex_master.fleet_",
        "codex_master.hive",
        "codex_master.queen_runtime",
        "codex_master.worker_resume",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            assert all(alias.name in allowed_modules for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            assert node.module in allowed_modules
            assert node.module not in forbidden_modules
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                assert node.func.id not in {"open", "exec", "eval", "compile", "__import__", "import_module"}
            if isinstance(node.func, ast.Attribute):
                root = node.func.value.id if isinstance(node.func.value, ast.Name) else None
                assert (root, node.func.attr) not in {
                    ("os", "system"),
                    ("os", "popen"),
                    ("subprocess", "run"),
                    ("subprocess", "Popen"),
                    ("socket", "socket"),
                    ("ssl", "create_default_context"),
                }
    assert "class AdminRequestV1" not in inspect.getsource(module)
    assert "AdminRequestV1(" not in inspect.getsource(module)
    assert "arguments" not in CanonicalMcpToolBindingV1.__dataclass_fields__
    assert "expected_generation" not in CanonicalMcpToolBindingV1.__dataclass_fields__
    assert "idempotency_key" not in CanonicalMcpToolBindingV1.__dataclass_fields__
    assert "plan_digest" not in CanonicalMcpToolBindingV1.__dataclass_fields__


def test_importing_contract_has_no_port_calls_or_mutable_runtime_state():
    import codex_master.remote_queen_mcp as module

    assert not [name for name in vars(module) if name.endswith("CACHE") or name.endswith("_CACHE")]
    assert not hasattr(module, "_PORT")
    assert isinstance(module.RemoteQueenMcpOperations, type)
    assert all(not callable(value) for name, value in vars(module).items() if name.startswith("_PORT"))
