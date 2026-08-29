import ast
import hashlib
import inspect
import json
from dataclasses import fields
from pathlib import Path

import pytest

from codex_master import remote_queen_codex as rq
from codex_master.remote_queen_bootstrap import ManifestGenerationV1
from codex_master.remote_queen_bootstrap import RemoteQueenBootstrapError


DESIRED_GENERATION = "rq-codex-2026-08-29"
CATALOG_GENERATION = "masterjet-client-catalog-2026-08-29"
INSTALLER_GENERATION = "standalone-installer-2026-08-29-test"
EXPECTED_VERSION = "codex-cli 1.2.3"


def _generation(value: str, digest: str = "a" * 64) -> ManifestGenerationV1:
    return ManifestGenerationV1(generation=value, sha256=digest)


def _build_manifest(**overrides):
    values = {
        "desired_generation": _generation(DESIRED_GENERATION, "a" * 64),
        "catalog_generation": _generation(CATALOG_GENERATION, "b" * 64),
        "installer_generation": INSTALLER_GENERATION,
        "installer_sha256": "c" * 64,
        "architecture": "x86_64",
        "expected_version": EXPECTED_VERSION,
        "expected_binary_sha256": "d" * 64,
        "remote_home": "/home/queen",
        "expected_owner_uid": 1000,
    }
    values.update(overrides)
    return rq.build_remote_queen_codex_manifest(**values)


def _assert_code(callable_obj, code: str = "RQ_E_PLAN_INCONSISTENT"):
    with pytest.raises(RemoteQueenBootstrapError) as exc_info:
        callable_obj()
    assert exc_info.value.code == code
    assert str(exc_info.value) == code


def test_official_source_constants_and_kind_are_exact():
    assert rq.OPENAI_CODEX_CLI_DOCUMENTATION_URL == (
        "https://developers.openai.com/codex/cli/"
    )
    assert rq.OPENAI_CODEX_STANDALONE_INSTALLER_URL == (
        "https://chatgpt.com/codex/install.sh"
    )

    manifest = _build_manifest()
    assert manifest.source.kind == "openai-standalone-installer"
    assert manifest.source.documentation_url == rq.OPENAI_CODEX_CLI_DOCUMENTATION_URL
    assert manifest.source.installer_url == rq.OPENAI_CODEX_STANDALONE_INSTALLER_URL


def test_builder_has_no_url_parameters():
    parameters = inspect.signature(rq.build_remote_queen_codex_manifest).parameters
    assert "documentation_url" not in parameters
    assert "installer_url" not in parameters
    with pytest.raises(TypeError):
        rq.build_remote_queen_codex_manifest(
            **{
                "desired_generation": _generation(DESIRED_GENERATION, "a" * 64),
                "catalog_generation": _generation(CATALOG_GENERATION, "b" * 64),
                "installer_generation": INSTALLER_GENERATION,
                "installer_sha256": "c" * 64,
                "architecture": "x86_64",
                "expected_version": EXPECTED_VERSION,
                "expected_binary_sha256": "d" * 64,
                "remote_home": "/home/queen",
                "expected_owner_uid": 1000,
                "installer_url": "https://evil.example/install.sh",
            }
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("kind", "other"),
        ("documentation_url", "https://evil.example/docs"),
        ("installer_url", "https://evil.example/install.sh"),
    ],
)
def test_source_rejects_non_official_direct_values(field, value):
    values = {
        "kind": "openai-standalone-installer",
        "documentation_url": rq.OPENAI_CODEX_CLI_DOCUMENTATION_URL,
        "installer_url": rq.OPENAI_CODEX_STANDALONE_INSTALLER_URL,
        "installer_generation": INSTALLER_GENERATION,
        "installer_sha256": "c" * 64,
    }
    values[field] = value
    _assert_code(lambda: rq.CodexStandaloneSourceV1(**values))


@pytest.mark.parametrize(
    "value",
    ["", " ", "latest", "stable", "daily", "main", "HEAD", "x\n", "é", "x" * 129],
)
def test_builder_rejects_unpinned_or_malformed_installer_generation(value):
    _assert_code(lambda: _build_manifest(installer_generation=value))


@pytest.mark.parametrize("value", ["latest", "stable", "daily", "main", "HEAD", " ", "x\n", "x" * 129])
def test_builder_rejects_unpinned_manifest_generations(value):
    _assert_code(
        lambda: _build_manifest(
            desired_generation=_generation(value, "a" * 64),
        )
    )
    _assert_code(
        lambda: _build_manifest(
            catalog_generation=_generation(value, "b" * 64),
        )
    )


@pytest.mark.parametrize("field", ["installer_sha256", "expected_binary_sha256"])
@pytest.mark.parametrize("value", ["a" * 63, "A" * 64, "sha256:" + "a" * 64, "a" * 65, "é" * 64])
def test_builder_rejects_unprefixed_lowercase_sha256_only(field, value):
    _assert_code(lambda: _build_manifest(**{field: value}))


@pytest.mark.parametrize(
    "value",
    ["", " ", "latest", "codex >= 1.2.3", "codex-*", "é", "x" * 129],
)
def test_builder_rejects_malformed_expected_version(value):
    _assert_code(lambda: _build_manifest(expected_version=value))


@pytest.mark.parametrize("value", ["x86_64", "aarch64"])
def test_builder_accepts_only_closed_linux_architectures(value):
    assert _build_manifest(architecture=value).platform == "linux"


@pytest.mark.parametrize("value", ["darwin", "linux-x86_64", "", "x86_64\n"])
def test_builder_rejects_unsupported_architecture(value):
    _assert_code(lambda: _build_manifest(architecture=value))


@pytest.mark.parametrize("value", [True, False, -1, 1.0, "1000"])
def test_builder_rejects_invalid_owner_uid(value):
    _assert_code(lambda: _build_manifest(expected_owner_uid=value))


@pytest.mark.parametrize(
    "value",
    [
        "/",
        "relative/home",
        "~/queen",
        "/home/queen/",
        "/home//queen",
        "/home/../queen",
        "/home/queen/..",
        "/home/queen/.",
        "/home/queen/\n",
        "/home/queen\t",
        "/home/que\u2028n",
    ],
)
def test_builder_rejects_unsafe_remote_home(value):
    _assert_code(lambda: _build_manifest(remote_home=value))


def test_builder_derives_only_canonical_target_paths():
    manifest = _build_manifest(remote_home="/srv/queen")
    assert manifest.install_path == "/srv/queen/.local/bin/codex"
    assert manifest.config_path == "/srv/queen/.codex/config.toml"


def test_manifest_dict_and_fixed_digest_vector_are_exact():
    manifest = _build_manifest()
    assert rq.codex_manifest_as_dict(manifest) == {
        "schema_version": "RemoteQueenCodexManifestV1",
        "desired_generation": {
            "generation": DESIRED_GENERATION,
            "sha256": "a" * 64,
        },
        "catalog_generation": {
            "generation": CATALOG_GENERATION,
            "sha256": "b" * 64,
        },
        "source": {
            "kind": "openai-standalone-installer",
            "documentation_url": rq.OPENAI_CODEX_CLI_DOCUMENTATION_URL,
            "installer_url": rq.OPENAI_CODEX_STANDALONE_INSTALLER_URL,
            "installer_generation": INSTALLER_GENERATION,
            "installer_sha256": "c" * 64,
        },
        "platform": "linux",
        "architecture": "x86_64",
        "expected_version": EXPECTED_VERSION,
        "expected_binary_sha256": "d" * 64,
        "expected_owner_uid": 1000,
        "install_path": "/home/queen/.local/bin/codex",
        "config_path": "/home/queen/.codex/config.toml",
        "manifest_digest": "sha256:0574f066291968d3bfd81af6957495bd22eac601043f33e42d9082c20626fd8c",
    }
    assert manifest.manifest_digest == (
        "sha256:0574f066291968d3bfd81af6957495bd22eac601043f33e42d9082c20626fd8c"
    )


def _absent_fact():
    return rq.CodexInstallFactV1(
        state=rq.CodexInstallStateKindV1.ABSENT,
        generation=None,
        install_path=None,
        owner_uid=None,
        reported_version=None,
        binary_sha256=None,
        installer_generation=None,
        installer_sha256=None,
        source_url=None,
        config_path=None,
        cli_start_ok=False,
        mcp_list_ok=False,
        resume_supported=False,
    )


def _owned_fact(manifest, **overrides):
    values = {
        "state": rq.CodexInstallStateKindV1.OWNED,
        "generation": manifest.desired_generation.generation,
        "install_path": manifest.install_path,
        "owner_uid": manifest.expected_owner_uid,
        "reported_version": manifest.expected_version,
        "binary_sha256": manifest.expected_binary_sha256,
        "installer_generation": manifest.source.installer_generation,
        "installer_sha256": manifest.source.installer_sha256,
        "source_url": manifest.source.installer_url,
        "config_path": manifest.config_path,
        "cli_start_ok": True,
        "mcp_list_ok": True,
        "resume_supported": True,
    }
    values.update(overrides)
    return rq.CodexInstallFactV1(**values)


class _InspectOnlyOperations:
    def __init__(self, fact):
        self.fact = fact
        self.calls = []

    def inspect(self, manifest):
        self.calls.append(("inspect", manifest))
        return self.fact


def test_absent_plan_is_install_and_matches_fixed_plan_vector():
    manifest = _build_manifest()
    operations = _InspectOnlyOperations(_absent_fact())
    plan = rq.plan_remote_queen_codex(manifest=manifest, operations=operations)

    assert operations.calls == [("inspect", manifest)]
    assert plan.action is rq.CodexPlanActionV1.INSTALL
    assert plan.before == _absent_fact()
    assert plan.before_digest == (
        "sha256:11c163998a7299cf8017e4adba474943acfaf661d43ed093eb5d77e03c0fa822"
    )
    assert rq.codex_plan_as_dict(plan) == {
        "schema_version": "RemoteQueenCodexPlanV1",
        "manifest": rq.codex_manifest_as_dict(manifest),
        "before": {
            "state": "absent",
            "generation": None,
            "install_path": None,
            "owner_uid": None,
            "reported_version": None,
            "binary_sha256": None,
            "installer_generation": None,
            "installer_sha256": None,
            "source_url": None,
            "config_path": None,
            "cli_start_ok": False,
            "mcp_list_ok": False,
            "resume_supported": False,
        },
        "before_digest": "sha256:11c163998a7299cf8017e4adba474943acfaf661d43ed093eb5d77e03c0fa822",
        "action": "install",
        "plan_digest": "sha256:52565c831a7f2c7eb09652aad4a42cb16158ec36fd912057123d053bc0bc3d6f",
    }


def test_exact_owned_plan_is_noop():
    manifest = _build_manifest()
    fact = _owned_fact(manifest)
    plan = rq.plan_remote_queen_codex(
        manifest=manifest,
        operations=_InspectOnlyOperations(fact),
    )
    assert plan.action is None
    assert plan.before == fact


def test_owned_older_generation_plans_replace():
    manifest = _build_manifest()
    fact = _owned_fact(
        manifest,
        generation="rq-codex-2026-08-28",
        reported_version="codex-cli 1.2.2",
        binary_sha256="e" * 64,
        installer_generation="standalone-installer-2026-08-28",
        installer_sha256="f" * 64,
    )
    plan = rq.plan_remote_queen_codex(
        manifest=manifest,
        operations=_InspectOnlyOperations(fact),
    )
    assert plan.action is rq.CodexPlanActionV1.REPLACE_OWNED


def test_foreign_state_blocks_without_leaking_fact():
    manifest = _build_manifest()
    fact = _owned_fact(
        manifest,
        state=rq.CodexInstallStateKindV1.FOREIGN,
        install_path="/srv/secret-rb3-do-not-retain/.local/bin/codex",
        config_path="/srv/secret-rb3-do-not-retain/.codex/config.toml",
    )
    with pytest.raises(RemoteQueenBootstrapError) as exc_info:
        rq.plan_remote_queen_codex(
            manifest=manifest,
            operations=_InspectOnlyOperations(fact),
        )
    assert exc_info.value.code == "RQ_E_FOREIGN_STATE"
    assert str(exc_info.value) == "RQ_E_FOREIGN_STATE"
    assert "secret-rb3-do-not-retain" not in str(exc_info.value)


@pytest.mark.parametrize(
    "field",
    ["owner_uid", "install_path", "config_path"],
)
def test_owned_wrong_identity_or_path_is_foreign(field):
    manifest = _build_manifest()
    value = {
        "owner_uid": 2000,
        "install_path": "/srv/other/.local/bin/codex",
        "config_path": "/srv/other/.codex/config.toml",
    }[field]
    with pytest.raises(RemoteQueenBootstrapError) as exc_info:
        rq.plan_remote_queen_codex(
            manifest=manifest,
            operations=_InspectOnlyOperations(_owned_fact(manifest, **{field: value})),
        )
    assert exc_info.value.code == "RQ_E_FOREIGN_STATE"


def test_owned_non_official_source_blocks_attestation():
    manifest = _build_manifest()
    with pytest.raises(RemoteQueenBootstrapError) as exc_info:
        rq.plan_remote_queen_codex(
            manifest=manifest,
            operations=_InspectOnlyOperations(
                _owned_fact(manifest, source_url="https://foreign.example/codex")
            ),
        )
    assert exc_info.value.code == "RQ_E_CODEX_ATTESTATION"
    assert str(exc_info.value) == "RQ_E_CODEX_ATTESTATION"


@pytest.mark.parametrize(
    "field",
    [
        "reported_version",
        "binary_sha256",
        "installer_generation",
        "installer_sha256",
        "cli_start_ok",
        "mcp_list_ok",
        "resume_supported",
    ],
)
def test_sollgeneration_with_bad_attestation_blocks(field):
    manifest = _build_manifest()
    values = {
        "generation": "rq-codex-other",
        "reported_version": "codex-cli 9.9.9",
        "binary_sha256": "e" * 64,
        "installer_generation": "standalone-installer-other",
        "installer_sha256": "f" * 64,
        "cli_start_ok": False,
        "mcp_list_ok": False,
        "resume_supported": False,
    }
    with pytest.raises(RemoteQueenBootstrapError) as exc_info:
        rq.plan_remote_queen_codex(
            manifest=manifest,
            operations=_InspectOnlyOperations(
                _owned_fact(manifest, **{field: values[field]})
            ),
        )
    assert exc_info.value.code == "RQ_E_CODEX_ATTESTATION"


def test_stale_owned_state_without_full_read_only_probes_blocks():
    manifest = _build_manifest()
    with pytest.raises(RemoteQueenBootstrapError) as exc_info:
        rq.plan_remote_queen_codex(
            manifest=manifest,
            operations=_InspectOnlyOperations(
                _owned_fact(
                    manifest,
                    generation="rq-codex-2026-08-28",
                    cli_start_ok=False,
                )
            ),
        )
    assert exc_info.value.code == "RQ_E_CODEX_ATTESTATION"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("generation", "bad\nvalue"),
        ("install_path", "/srv/other/../codex"),
        ("owner_uid", True),
        ("binary_sha256", "not-a-digest"),
        ("cli_start_ok", 1),
    ],
)
def test_fact_rejects_malformed_or_contradictory_types(field, value):
    manifest = _build_manifest()
    _assert_code(lambda: _owned_fact(manifest, **{field: value}))


@pytest.mark.parametrize(
    "field",
    [
        "generation",
        "install_path",
        "owner_uid",
        "reported_version",
        "binary_sha256",
        "installer_generation",
        "installer_sha256",
        "source_url",
        "config_path",
        "cli_start_ok",
        "mcp_list_ok",
        "resume_supported",
    ],
)
def test_absent_fact_requires_all_attestation_fields_null_or_false(field):
    defaults = {
        "generation": "rq-codex-other",
        "install_path": "/srv/other/.local/bin/codex",
        "owner_uid": 1000,
        "reported_version": "codex-cli 1.2.3",
        "binary_sha256": "a" * 64,
        "installer_generation": "standalone-installer-other",
        "installer_sha256": "b" * 64,
        "source_url": rq.OPENAI_CODEX_STANDALONE_INSTALLER_URL,
        "config_path": "/srv/other/.codex/config.toml",
        "cli_start_ok": True,
        "mcp_list_ok": True,
        "resume_supported": True,
    }
    values = {
        key: (None if key not in {"cli_start_ok", "mcp_list_ok", "resume_supported"} else False)
        for key in defaults
    }
    values[field] = defaults[field]
    _assert_code(
        lambda: rq.CodexInstallFactV1(
            state=rq.CodexInstallStateKindV1.ABSENT,
            **values,
        )
    )


def test_manifest_and_plan_digests_change_when_bound_manifest_inputs_change():
    manifest = _build_manifest()
    variants = [
        {"desired_generation": _generation("rq-codex-other", "e" * 64)},
        {"catalog_generation": _generation("catalog-other", "f" * 64)},
        {"installer_generation": "standalone-installer-other"},
        {"installer_sha256": "e" * 64},
        {"architecture": "aarch64"},
        {"expected_version": "codex-cli 1.2.4"},
        {"expected_binary_sha256": "e" * 64},
        {"remote_home": "/srv/queen"},
        {"expected_owner_uid": 1001},
    ]
    assert all(_build_manifest(**variant).manifest_digest != manifest.manifest_digest for variant in variants)


def test_plan_digest_is_deterministic_and_binds_before_fact():
    manifest = _build_manifest()
    first = rq.plan_remote_queen_codex(
        manifest=manifest,
        operations=_InspectOnlyOperations(_absent_fact()),
    )
    second = rq.plan_remote_queen_codex(
        manifest=manifest,
        operations=_InspectOnlyOperations(_absent_fact()),
    )
    assert first == second
    stale = _owned_fact(manifest, generation="rq-codex-2026-08-28")
    changed = rq.plan_remote_queen_codex(
        manifest=manifest,
        operations=_InspectOnlyOperations(stale),
    )
    assert changed.before_digest != first.before_digest
    assert changed.plan_digest != first.plan_digest


def _fact_digest_for_test(fact):
    payload = {
        "state": fact.state.value,
        "generation": fact.generation,
        "install_path": fact.install_path,
        "owner_uid": fact.owner_uid,
        "reported_version": fact.reported_version,
        "binary_sha256": fact.binary_sha256,
        "installer_generation": fact.installer_generation,
        "installer_sha256": fact.installer_sha256,
        "source_url": fact.source_url,
        "config_path": fact.config_path,
        "cli_start_ok": fact.cli_start_ok,
        "mcp_list_ok": fact.mcp_list_ok,
        "resume_supported": fact.resume_supported,
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(canonical.encode()).hexdigest()


def _apply_request(manifest, plan):
    return rq.CodexApplyRequestV1(
        generation=manifest.desired_generation.generation,
        manifest_digest=manifest.manifest_digest,
        plan_digest=plan.plan_digest,
    )


def _verify_request(manifest):
    return rq.CodexVerifyRequestV1(
        generation=manifest.desired_generation.generation,
        manifest_digest=manifest.manifest_digest,
    )


def _rollback_request(manifest, plan):
    return rq.CodexRollbackRequestV1(
        generation=manifest.desired_generation.generation,
        manifest_digest=manifest.manifest_digest,
        plan_digest=plan.plan_digest,
    )


class _FakeCodexOperations:
    def __init__(self, fact, post_fact=None, *, install_error=None, rollback_error=None):
        self.fact = fact
        self.post_fact = post_fact
        self.install_error = install_error
        self.rollback_error = rollback_error
        self.calls = []

    def inspect(self, manifest):
        self.calls.append(("inspect", manifest))
        return self.fact

    def install_attested(self, plan):
        self.calls.append(("install_attested", plan))
        if self.install_error is not None:
            raise self.install_error
        prior = self.fact
        self.fact = self.post_fact
        return rq.CodexApplyJournalV1(
            schema_version="CodexApplyJournalV1",
            generation=plan.manifest.desired_generation.generation,
            manifest_digest=plan.manifest.manifest_digest,
            plan_digest=plan.plan_digest,
            prior=prior,
            resulting_fact_digest=_fact_digest_for_test(self.fact),
        )

    def rollback_installation(self, plan, journal):
        self.calls.append(("rollback_installation", plan, journal))
        if self.rollback_error is not None:
            raise self.rollback_error
        self.fact = journal.prior


def test_apply_success_has_exact_call_sequence_journal_and_attestation():
    manifest = _build_manifest()
    post_fact = _owned_fact(manifest)
    operations = _FakeCodexOperations(_absent_fact(), post_fact)
    plan = rq.plan_remote_queen_codex(manifest=manifest, operations=operations)
    operations.calls.clear()

    result = rq.apply_remote_queen_codex(
        plan=plan,
        request=_apply_request(manifest, plan),
        operations=operations,
    )

    assert [call[0] for call in operations.calls] == [
        "inspect",
        "install_attested",
        "inspect",
    ]
    assert operations.calls[1][1] is plan
    assert result.changed is True
    assert result.journal is not None
    assert result.journal.schema_version == "CodexApplyJournalV1"
    assert result.journal.generation == manifest.desired_generation.generation
    assert result.journal.manifest_digest == manifest.manifest_digest
    assert result.journal.plan_digest == plan.plan_digest
    assert result.journal.prior == plan.before
    assert result.journal.resulting_fact_digest == _fact_digest_for_test(post_fact)
    assert result.fact_digest == _fact_digest_for_test(post_fact)


def test_apply_noop_never_calls_install():
    manifest = _build_manifest()
    operations = _FakeCodexOperations(_owned_fact(manifest))
    plan = rq.plan_remote_queen_codex(manifest=manifest, operations=operations)
    operations.calls.clear()

    result = rq.apply_remote_queen_codex(
        plan=plan,
        request=_apply_request(manifest, plan),
        operations=operations,
    )

    assert plan.action is None
    assert [call[0] for call in operations.calls] == ["inspect"]
    assert result == rq.CodexApplyResultV1(
        changed=False,
        journal=None,
        fact_digest=_fact_digest_for_test(operations.fact),
    )


@pytest.mark.parametrize("field", ["generation", "manifest_digest", "plan_digest"])
def test_apply_request_binding_mismatch_blocks_before_inspect(field):
    manifest = _build_manifest()
    operations = _FakeCodexOperations(_absent_fact())
    plan = rq.plan_remote_queen_codex(manifest=manifest, operations=operations)
    request_values = {
        "generation": manifest.desired_generation.generation,
        "manifest_digest": manifest.manifest_digest,
        "plan_digest": plan.plan_digest,
    }
    request_values[field] = {
        "generation": "rq-codex-other",
        "manifest_digest": "sha256:" + "e" * 64,
        "plan_digest": "sha256:" + "f" * 64,
    }[field]
    request = rq.CodexApplyRequestV1(**request_values)
    operations.calls.clear()

    with pytest.raises(RemoteQueenBootstrapError) as exc_info:
        rq.apply_remote_queen_codex(plan=plan, request=request, operations=operations)
    assert exc_info.value.code == "RQ_E_PLAN_INCONSISTENT"
    assert operations.calls == []


def test_apply_before_drift_blocks_before_install():
    manifest = _build_manifest()
    operations = _FakeCodexOperations(_absent_fact())
    plan = rq.plan_remote_queen_codex(manifest=manifest, operations=operations)
    operations.fact = _owned_fact(manifest)
    operations.calls.clear()

    with pytest.raises(RemoteQueenBootstrapError) as exc_info:
        rq.apply_remote_queen_codex(
            plan=plan,
            request=_apply_request(manifest, plan),
            operations=operations,
        )
    assert exc_info.value.code == "RQ_E_CODEX_ATTESTATION"
    assert [call[0] for call in operations.calls] == ["inspect"]


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("source_url", "https://foreign.example/codex"),
        ("installer_generation", "standalone-installer-other"),
        ("installer_sha256", "e" * 64),
        ("reported_version", "codex-cli 9.9.9"),
        ("binary_sha256", "e" * 64),
        ("owner_uid", 1001),
        ("install_path", "/srv/other/.local/bin/codex"),
        ("config_path", "/srv/other/.codex/config.toml"),
        ("cli_start_ok", False),
        ("mcp_list_ok", False),
        ("resume_supported", False),
    ],
)
def test_apply_wrong_postfact_blocks_after_install_and_post_inspect(field, value):
    manifest = _build_manifest()
    operations = _FakeCodexOperations(
        _absent_fact(),
        _owned_fact(manifest, **{field: value}),
    )
    plan = rq.plan_remote_queen_codex(manifest=manifest, operations=operations)
    operations.calls.clear()

    with pytest.raises(RemoteQueenBootstrapError) as exc_info:
        rq.apply_remote_queen_codex(
            plan=plan,
            request=_apply_request(manifest, plan),
            operations=operations,
        )
    assert exc_info.value.code == "RQ_E_CODEX_ATTESTATION"
    assert [call[0] for call in operations.calls] == [
        "inspect",
        "install_attested",
        "inspect",
    ]


def test_apply_then_replan_is_noop():
    manifest = _build_manifest()
    operations = _FakeCodexOperations(_absent_fact(), _owned_fact(manifest))
    first_plan = rq.plan_remote_queen_codex(manifest=manifest, operations=operations)
    rq.apply_remote_queen_codex(
        plan=first_plan,
        request=_apply_request(manifest, first_plan),
        operations=operations,
    )
    operations.calls.clear()

    second_plan = rq.plan_remote_queen_codex(manifest=manifest, operations=operations)
    assert second_plan.action is None
    assert [call[0] for call in operations.calls] == ["inspect"]


def test_verify_is_read_only_and_requires_full_attestation():
    manifest = _build_manifest()
    operations = _FakeCodexOperations(_owned_fact(manifest))
    result = rq.verify_remote_queen_codex(
        manifest=manifest,
        request=_verify_request(manifest),
        operations=operations,
    )
    assert result.fact_digest == _fact_digest_for_test(operations.fact)
    assert [call[0] for call in operations.calls] == ["inspect"]


def test_verify_bad_fact_blocks_without_repair():
    manifest = _build_manifest()
    operations = _FakeCodexOperations(
        _owned_fact(manifest, mcp_list_ok=False),
    )
    with pytest.raises(RemoteQueenBootstrapError) as exc_info:
        rq.verify_remote_queen_codex(
            manifest=manifest,
            request=_verify_request(manifest),
            operations=operations,
        )
    assert exc_info.value.code == "RQ_E_CODEX_ATTESTATION"
    assert [call[0] for call in operations.calls] == ["inspect"]


def test_rollback_restores_exact_prior_fact_and_call_sequence():
    manifest = _build_manifest()
    operations = _FakeCodexOperations(_absent_fact(), _owned_fact(manifest))
    plan = rq.plan_remote_queen_codex(manifest=manifest, operations=operations)
    apply_result = rq.apply_remote_queen_codex(
        plan=plan,
        request=_apply_request(manifest, plan),
        operations=operations,
    )
    assert apply_result.journal is not None
    operations.calls.clear()

    result = rq.rollback_remote_queen_codex(
        plan=plan,
        journal=apply_result.journal,
        request=_rollback_request(manifest, plan),
        operations=operations,
    )

    assert [call[0] for call in operations.calls] == [
        "inspect",
        "rollback_installation",
        "inspect",
    ]
    assert operations.fact == plan.before
    assert result.restored_fact_digest == _fact_digest_for_test(plan.before)


def test_rollback_drift_blocks_without_rollback_call():
    manifest = _build_manifest()
    operations = _FakeCodexOperations(_absent_fact(), _owned_fact(manifest))
    plan = rq.plan_remote_queen_codex(manifest=manifest, operations=operations)
    apply_result = rq.apply_remote_queen_codex(
        plan=plan,
        request=_apply_request(manifest, plan),
        operations=operations,
    )
    assert apply_result.journal is not None
    operations.fact = _owned_fact(manifest, binary_sha256="e" * 64)
    operations.calls.clear()

    with pytest.raises(RemoteQueenBootstrapError) as exc_info:
        rq.rollback_remote_queen_codex(
            plan=plan,
            journal=apply_result.journal,
            request=_rollback_request(manifest, plan),
            operations=operations,
        )
    assert exc_info.value.code == "RQ_E_ROLLBACK_DRIFT"
    assert [call[0] for call in operations.calls] == ["inspect"]


def test_rollback_foreign_state_blocks_without_rollback_call():
    manifest = _build_manifest()
    operations = _FakeCodexOperations(_absent_fact(), _owned_fact(manifest))
    plan = rq.plan_remote_queen_codex(manifest=manifest, operations=operations)
    apply_result = rq.apply_remote_queen_codex(
        plan=plan,
        request=_apply_request(manifest, plan),
        operations=operations,
    )
    assert apply_result.journal is not None
    operations.fact = _owned_fact(
        manifest,
        state=rq.CodexInstallStateKindV1.FOREIGN,
        install_path="/srv/foreign/.local/bin/codex",
        config_path="/srv/foreign/.codex/config.toml",
    )
    operations.calls.clear()

    with pytest.raises(RemoteQueenBootstrapError) as exc_info:
        rq.rollback_remote_queen_codex(
            plan=plan,
            journal=apply_result.journal,
            request=_rollback_request(manifest, plan),
            operations=operations,
        )
    assert exc_info.value.code == "RQ_E_ROLLBACK_DRIFT"
    assert [call[0] for call in operations.calls] == ["inspect"]


@pytest.mark.parametrize("field", ["generation", "manifest_digest", "plan_digest", "prior"])
def test_rollback_stale_journal_blocks_before_rollback_call(field):
    manifest = _build_manifest()
    operations = _FakeCodexOperations(_absent_fact(), _owned_fact(manifest))
    plan = rq.plan_remote_queen_codex(manifest=manifest, operations=operations)
    apply_result = rq.apply_remote_queen_codex(
        plan=plan,
        request=_apply_request(manifest, plan),
        operations=operations,
    )
    assert apply_result.journal is not None
    journal_values = {
        "schema_version": apply_result.journal.schema_version,
        "generation": apply_result.journal.generation,
        "manifest_digest": apply_result.journal.manifest_digest,
        "plan_digest": apply_result.journal.plan_digest,
        "prior": apply_result.journal.prior,
        "resulting_fact_digest": apply_result.journal.resulting_fact_digest,
    }
    journal_values[field] = {
        "generation": "rq-codex-other",
        "manifest_digest": "sha256:" + "e" * 64,
        "plan_digest": "sha256:" + "f" * 64,
        "prior": _owned_fact(manifest, generation="rq-codex-other"),
    }[field]
    journal = rq.CodexApplyJournalV1(**journal_values)
    operations.calls.clear()

    with pytest.raises(RemoteQueenBootstrapError) as exc_info:
        rq.rollback_remote_queen_codex(
            plan=plan,
            journal=journal,
            request=_rollback_request(manifest, plan),
            operations=operations,
        )
    assert exc_info.value.code == "RQ_E_PLAN_INCONSISTENT"
    assert operations.calls == []


@pytest.mark.parametrize("operation", ["inspect", "install", "rollback"])
def test_operations_exceptions_are_redacted_and_fail_closed(operation):
    manifest = _build_manifest()
    if operation == "inspect":
        operations = _FakeCodexOperations(
            _absent_fact(),
            install_error=RuntimeError("secret-rb3-do-not-retain"),
        )
        operations.inspect = lambda _manifest: (_ for _ in ()).throw(
            RuntimeError("secret-rb3-do-not-retain")
        )
        with pytest.raises(RemoteQueenBootstrapError) as exc_info:
            rq.plan_remote_queen_codex(manifest=manifest, operations=operations)
    elif operation == "install":
        operations = _FakeCodexOperations(
            _absent_fact(),
            _owned_fact(manifest),
            install_error=RuntimeError("secret-rb3-do-not-retain"),
        )
        plan = rq.plan_remote_queen_codex(manifest=manifest, operations=operations)
        with pytest.raises(RemoteQueenBootstrapError) as exc_info:
            rq.apply_remote_queen_codex(
                plan=plan,
                request=_apply_request(manifest, plan),
                operations=operations,
            )
    else:
        operations = _FakeCodexOperations(_absent_fact(), _owned_fact(manifest))
        plan = rq.plan_remote_queen_codex(manifest=manifest, operations=operations)
        apply_result = rq.apply_remote_queen_codex(
            plan=plan,
            request=_apply_request(manifest, plan),
            operations=operations,
        )
        assert apply_result.journal is not None
        operations.rollback_error = RuntimeError("secret-rb3-do-not-retain")
        with pytest.raises(RemoteQueenBootstrapError) as exc_info:
            rq.rollback_remote_queen_codex(
                plan=plan,
                journal=apply_result.journal,
                request=_rollback_request(manifest, plan),
                operations=operations,
            )
    assert exc_info.value.code == "RQ_E_CODEX_ATTESTATION"
    assert "secret-rb3-do-not-retain" not in str(exc_info.value)


def _dotted_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _dotted_name(node.value)
        return None if prefix is None else prefix + "." + node.attr
    return None


def test_import_and_call_ast_gate_has_no_external_or_effectful_surface():
    source = Path(rq.__file__).read_text()
    tree = ast.parse(source)
    forbidden_namespaces = {
        "os",
        "subprocess",
        "socket",
        "asyncio",
        "requests",
        "urllib",
        "http",
        "httpx",
        "aiohttp",
        "paramiko",
        "asyncssh",
        "tempfile",
        "shutil",
        "pathlib.Path",
        "pip",
        "npm",
    }
    forbidden_calls = {
        "open",
        "system",
        "popen",
        "run",
        "call",
        "check_call",
        "check_output",
        "Popen",
        "connect",
        "urlopen",
        "request",
        "get",
        "post",
        "put",
        "download",
        "read_text",
        "read_bytes",
        "write_text",
        "write_bytes",
        "unlink",
        "rename",
        "chmod",
        "mkdir",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported = [alias.name for alias in node.names]
            assert not any(
                name == forbidden or name.startswith(forbidden + ".")
                for name in imported
                for forbidden in forbidden_namespaces
            )
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            imported = [module + "." + alias.name for alias in node.names]
            assert not any(
                name == forbidden or name.startswith(forbidden + ".")
                for name in imported
                for forbidden in forbidden_namespaces
            )
        elif isinstance(node, ast.Call):
            dotted = _dotted_name(node.func)
            if dotted is not None:
                assert dotted.split(".")[-1] not in forbidden_calls


def test_module_contains_no_download_shell_or_mutable_source_marker():
    source = Path(rq.__file__).read_text()
    for marker in (
        "curl",
        "npm install",
        "brew install",
        "latest",
        "StrictHostKeyChecking",
        "Installerbody",
        "stdout",
        "stderr",
    ):
        assert marker not in source


def test_public_dataclasses_have_no_secret_or_command_fields():
    public_types = (
        rq.CodexStandaloneSourceV1,
        rq.CodexInstallFactV1,
        rq.RemoteQueenCodexManifestV1,
        rq.RemoteQueenCodexPlanV1,
        rq.CodexApplyRequestV1,
        rq.CodexApplyJournalV1,
        rq.CodexApplyResultV1,
        rq.CodexVerifyRequestV1,
        rq.CodexVerifyResultV1,
        rq.CodexRollbackRequestV1,
        rq.CodexRollbackResultV1,
    )
    forbidden_field_fragments = (
        "auth",
        "token",
        "account",
        "cookie",
        "credential",
        "header",
        "password",
        "secret",
        "environment",
        "command",
        "stdout",
        "stderr",
        "body",
    )
    for public_type in public_types:
        for field in fields(public_type):
            assert not any(
                fragment in field.name.lower()
                for fragment in forbidden_field_fragments
            )


def test_secret_sentinel_from_fact_is_never_retained_or_serialized():
    manifest = _build_manifest()
    sentinel = "secret-rb3-do-not-retain"
    with pytest.raises(RemoteQueenBootstrapError) as exc_info:
        rq.plan_remote_queen_codex(
            manifest=manifest,
            operations=_InspectOnlyOperations(
                _owned_fact(manifest, reported_version=sentinel)
            ),
        )
    assert exc_info.value.code == "RQ_E_CODEX_ATTESTATION"
    assert sentinel not in str(exc_info.value)
    assert sentinel not in repr(exc_info.value)
    assert sentinel not in json.dumps(rq.codex_manifest_as_dict(manifest))


def test_operations_port_only_receives_typed_in_memory_values():
    manifest = _build_manifest()
    operations = _FakeCodexOperations(_absent_fact(), _owned_fact(manifest))
    plan = rq.plan_remote_queen_codex(manifest=manifest, operations=operations)
    operations.calls.clear()
    rq.apply_remote_queen_codex(
        plan=plan,
        request=_apply_request(manifest, plan),
        operations=operations,
    )
    assert type(operations.calls[1][1]) is rq.RemoteQueenCodexPlanV1
    assert all(
        call[0] in {"inspect", "install_attested", "rollback_installation"}
        for call in operations.calls
    )


def test_runtime_effect_rejects_non_url_source_without_retaining_value():
    _assert_code(
        lambda: _owned_fact(
            _build_manifest(),
            source_url="secret-rb3-do-not-retain",
        )
    )
