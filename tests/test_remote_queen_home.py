import ast
from dataclasses import FrozenInstanceError, fields, replace
from pathlib import Path

import pytest

from codex_master import remote_queen_home
from codex_master.remote_queen_bootstrap import ManifestGenerationV1, RemoteQueenBootstrapError
from codex_master.remote_queen_home import (
    GENERIC_RULES_PATH,
    QUEEN_BRANCH,
    QUEEN_HOME_PARENT,
    QUEEN_HOME_PREFIX,
    QUEEN_INTEGRATION_OWNER,
    QUEEN_REPO_DIR,
    QUEEN_REPO_ID,
    QUEEN_ROLE,
    QUEEN_TOPIC_ID,
    REMOTE_QUEEN_HOME_PLAN_SCHEMA,
    REMOTE_QUEEN_HOME_SCHEMA,
    RESUME_CAPSULE_SCHEMA,
    TOPIC_ASSIGNMENT_PATH,
    ApplyRemoteQueenHomeRequestV1,
    QueenHomeActionV1,
    QueenHomeFactV1,
    QueenHomeMaterialV1,
    QueenHomeSnapshotV1,
    QueenHomeStateKindV1,
    QueenLeaseBindingV1,
    QueenMaterialKindV1,
    QueenTopicBindingV1,
    RemoteQueenHomeApplyJournalV1,
    RemoteQueenHomeManifestV1,
    ResumeCapsuleV1,
    RollbackRemoteQueenHomeRequestV1,
    VerifyRemoteQueenHomeRequestV1,
    apply_remote_queen_home,
    build_queen_lease_binding,
    build_queen_topic_binding,
    build_remote_queen_home_manifest,
    build_resume_capsule,
    canonical_digest,
    canonical_json_bytes,
    material_tree_digest,
    plan_remote_queen_home,
    queen_home_snapshot_digest,
    rollback_remote_queen_home,
    verify_remote_queen_home,
)


BASELINE = "152a492c963e7bdfd9cab7491fb98757904269b4"
DESIRED_GENERATION = ManifestGenerationV1("rq-home-2026-08-29", "a" * 64)
CAPSULE_GENERATION = ManifestGenerationV1("rq-resume-2026-08-29", "b" * 64)
LEASE_GENERATION = ManifestGenerationV1("g18-lease-2026-08-29", "c" * 64)
WRITE_PATHS = ("G18/artifacts/**", "G18/plan/**")
AUTH_PLAN_DIGEST = "sha256:" + "d" * 64
BUS_CURSOR_DIGEST = "sha256:" + "f" * 64
ACCOUNT_DIGEST = "sha256:" + "1" * 64
MATERIALS = (
    QueenHomeMaterialV1(
        "assignments/g18.md",
        QueenMaterialKindV1.TOPIC_ASSIGNMENT,
        "g18-topic-queen",
        "sha256:" + "6" * 64,
    ),
    QueenHomeMaterialV1(
        "instructions/generic.md",
        QueenMaterialKindV1.GENERIC_RULES,
        "generic",
        "sha256:" + "4" * 64,
    ),
    QueenHomeMaterialV1(
        "instructions/queen.md",
        QueenMaterialKindV1.QUEEN_RULES,
        "queen",
        "sha256:" + "5" * 64,
    ),
    QueenHomeMaterialV1(
        "skills/codex-master-fleet/SKILL.md",
        QueenMaterialKindV1.SKILL,
        "queen",
        "sha256:" + "7" * 64,
    ),
)
ACCEPTED_DIGESTS = tuple(sorted(material.content_sha256 for material in MATERIALS))


def _code(exc_info):
    return exc_info.value.code


def _expect_code(code, fn, *args, **kwargs):
    with pytest.raises(RemoteQueenBootstrapError) as caught:
        fn(*args, **kwargs)
    assert _code(caught) == code


def test_material_post_init_validates_new_instances_inside_test_context():
    material = QueenHomeMaterialV1(
        "instructions/generic.md",
        QueenMaterialKindV1.GENERIC_RULES,
        "generic",
        "sha256:" + "4" * 64,
    )
    assert material.relative_path == "instructions/generic.md"


def test_valid_digest_accepts_only_canonical_sha256_values():
    assert remote_queen_home._valid_digest("sha256:" + "a" * 64)
    assert not remote_queen_home._valid_digest("sha256:" + "A" * 64)


def test_valid_class_id_accepts_only_remote_queen_material_classes():
    assert remote_queen_home._valid_class_id("queen")
    assert not remote_queen_home._valid_class_id("teamleiterin")


def test_digest_without_own_field_matches_public_canonical_digest():
    topic = build_queen_topic_binding(WRITE_PATHS)
    assert remote_queen_home._digest_payload_without_field(topic) == canonical_digest(topic)


def _manifest():
    topic = build_queen_topic_binding(WRITE_PATHS)
    lease = build_queen_lease_binding("lease-g18-1", "queen-g18", 1, LEASE_GENERATION)
    capsule = build_resume_capsule(
        CAPSULE_GENERATION,
        "queen-g18",
        "session-g18-1",
        AUTH_PLAN_DIGEST,
        BASELINE,
        lease,
        BUS_CURSOR_DIGEST,
        ACCOUNT_DIGEST,
        ACCEPTED_DIGESTS,
    )
    return build_remote_queen_home_manifest(
        DESIRED_GENERATION,
        "/home/queen",
        topic,
        lease,
        MATERIALS,
        capsule,
    )


def _absent_snapshot(manifest, **overrides):
    values = dict(
        home=QueenHomeFactV1(
            QueenHomeStateKindV1.ABSENT,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        ),
        active_topic_principal_id=None,
        active_topic_home_path=None,
        active_topic_lease_id=None,
        conflicting_write_paths=(),
        lease_active=True,
        observed_lease_binding_digest=manifest.lease_binding.binding_digest,
        bus_available=True,
        observed_bus_cursor_sha256=manifest.resume_capsule.bus_cursor_sha256,
        account_available=True,
        observed_account_binding_sha256=manifest.resume_capsule.account_binding_sha256,
    )
    values.update(overrides)
    return QueenHomeSnapshotV1(**values)


def _partial_active_absent_snapshot(manifest):
    snapshot = _absent_snapshot(
        manifest,
        lease_active=False,
        observed_lease_binding_digest=None,
        observed_bus_cursor_sha256="sha256:" + "e" * 64,
    )
    object.__setattr__(
        snapshot,
        "active_topic_principal_id",
        manifest.lease_binding.owner_principal_id,
    )
    return snapshot


def _owned_snapshot(manifest, **overrides):
    values = dict(
        home=QueenHomeFactV1(
            QueenHomeStateKindV1.OWNED,
            manifest.desired_generation.generation,
            manifest.lease_binding.owner_principal_id,
            manifest.lease_binding.lease_id,
            manifest.home_path,
            manifest.manifest_digest,
            BASELINE,
            QUEEN_BRANCH,
            material_tree_digest(manifest.materials),
            manifest.resume_capsule.capsule_digest,
            manifest.resume_capsule.plan_digest,
            manifest.lease_binding.binding_digest,
            manifest.resume_capsule.bus_cursor_sha256,
        ),
        active_topic_principal_id=manifest.lease_binding.owner_principal_id,
        active_topic_home_path=manifest.home_path,
        active_topic_lease_id=manifest.lease_binding.lease_id,
        conflicting_write_paths=(),
        lease_active=True,
        observed_lease_binding_digest=manifest.lease_binding.binding_digest,
        bus_available=True,
        observed_bus_cursor_sha256=manifest.resume_capsule.bus_cursor_sha256,
        account_available=True,
        observed_account_binding_sha256=manifest.resume_capsule.account_binding_sha256,
    )
    values.update(overrides)
    return QueenHomeSnapshotV1(**values)


class FakeOperations:
    def __init__(self, inspect_results, journal=None, materialize_error=None, rollback_error=None):
        self.inspect_results = list(inspect_results)
        self.journal = journal
        self.materialize_error = materialize_error
        self.rollback_error = rollback_error
        self.calls = []

    def inspect(self, manifest):
        self.calls.append(("inspect", manifest))
        if not self.inspect_results:
            raise AssertionError("unexpected inspect")
        result = self.inspect_results.pop(0)
        if isinstance(result, BaseException):
            raise result
        return result

    def materialize_home(self, plan):
        self.calls.append(("materialize_home", plan))
        if self.materialize_error is not None:
            raise self.materialize_error
        return self.journal

    def rollback_home(self, plan, journal):
        self.calls.append(("rollback_home", plan, journal))
        if self.rollback_error is not None:
            raise self.rollback_error


def test_closed_constants_and_exact_immutable_public_shapes():
    assert REMOTE_QUEEN_HOME_SCHEMA == "remote-queen-home-v1"
    assert REMOTE_QUEEN_HOME_PLAN_SCHEMA == "remote-queen-home-plan-v1"
    assert RESUME_CAPSULE_SCHEMA == "resume-capsule-v1"
    assert QUEEN_REPO_ID == QUEEN_REPO_DIR == "codex-master"
    assert QUEEN_TOPIC_ID == QUEEN_BRANCH == "g18-vertex-overflow"
    assert QUEEN_ROLE == "queen"
    assert QUEEN_INTEGRATION_OWNER == "codex-master-integration-queen"
    assert QUEEN_HOME_PARENT == ".codex-agents/Queens"
    assert QUEEN_HOME_PREFIX == "G18-"
    assert GENERIC_RULES_PATH == "instructions/generic.md"
    assert TOPIC_ASSIGNMENT_PATH == "assignments/g18.md"
    assert [item.value for item in QueenHomeStateKindV1] == ["absent", "owned", "foreign"]
    assert [item.value for item in QueenHomeActionV1] == ["create-home"]
    assert [item.value for item in QueenMaterialKindV1] == [
        "generic-rules",
        "queen-rules",
        "topic-assignment",
        "skill",
    ]
    for cls in (
        QueenHomeMaterialV1,
        QueenTopicBindingV1,
        QueenLeaseBindingV1,
        ResumeCapsuleV1,
        RemoteQueenHomeManifestV1,
        QueenHomeFactV1,
        QueenHomeSnapshotV1,
    ):
        assert cls.__dataclass_params__.frozen
        assert hasattr(cls, "__slots__")
    assert [field.name for field in fields(QueenHomeMaterialV1)] == [
        "relative_path",
        "kind",
        "class_id",
        "content_sha256",
    ]
    manifest = _manifest()
    with pytest.raises(FrozenInstanceError):
        manifest.remote_home = "/elsewhere"
    _expect_code("RQ_E_PLAN_INCONSISTENT", build_queen_topic_binding, ["G18/plan/**"])
    _expect_code(
        "RQ_E_PLAN_INCONSISTENT",
        build_queen_lease_binding,
        "lease-g18-1",
        "queen-g18",
        True,
        LEASE_GENERATION,
    )


def test_canonicalization_and_fixed_seven_digest_vector():
    manifest = _manifest()
    assert manifest.topic_binding.binding_digest == "sha256:9ce316a8878da7aeff21b3752f3f7c50da2690e9ca508fcf149248882ffd510b"
    assert manifest.lease_binding.binding_digest == "sha256:5a3ce7f18c287b775d34fa8267bff7ee06eb5c99c7b8504181b21de44d68a7c1"
    assert manifest.resume_capsule.capsule_digest == "sha256:693967d176afdab8ab8de04351075330b5f3513d01f7e8456033f7f89d115fb4"
    assert material_tree_digest(manifest.materials) == "sha256:cefe490e933d4265d4d228db7f49d39ffaffe2903728aff8ca0b5d821ea70437"
    assert manifest.manifest_digest == "sha256:b167cb957392d5cab2472f25d969ea16cb20b1eaa4d81b1b528bee0923eae61e"
    before = _absent_snapshot(manifest)
    assert queen_home_snapshot_digest(before) == "sha256:2a05a0484bb5d9395fd6db984b6d4128c80cbf182274a4c9db03b1295e0cc1e3"
    plan = plan_remote_queen_home(manifest, FakeOperations([before]))
    assert plan.plan_digest == "sha256:1a3543ca3fb610cfff48811b1ee37ee17c7c0462428ee231138abc0e9f78c9fa"
    assert canonical_json_bytes(("b", "ä")) == '["b","ä"]'.encode("utf-8")
    assert canonical_digest({"z": 1, "a": True}) == "sha256:903596123ef8596d132eb70fae4c171f0133ed7cdbe9e3e6a67d01c08c5c6992"
    _expect_code("RQ_E_PLAN_INCONSISTENT", canonical_json_bytes, ["list-is-not-domain"])
    _expect_code("RQ_E_PLAN_INCONSISTENT", canonical_json_bytes, {1: "non-string-key"})
    _expect_code("RQ_E_PLAN_INCONSISTENT", canonical_json_bytes, float("nan"))
    _expect_code("RQ_E_PLAN_INCONSISTENT", canonical_json_bytes, b"secret")


def test_path_material_and_class_gates_are_fail_closed():
    manifest = _manifest()
    topic = manifest.topic_binding
    lease = manifest.lease_binding
    capsule = manifest.resume_capsule
    for write_paths in (
        ("G18/**",),
        ("/G18/plan/**",),
        ("G18/../plan/**",),
        ("G18/plan\\/**",),
        ("G18/plan/**", "G18/plan/sub/**"),
        ("G18/masterplan/**",),
        ("G18/bootstrapplan/**",),
    ):
        _expect_code("RQ_E_PLAN_INCONSISTENT", build_queen_topic_binding, write_paths)
    for remote_home in ("/", "/home/queen/", "/home/./queen", "/home//queen", "home/queen", "/home/../queen", "/home/que\u0000n"):
        _expect_code(
            "RQ_E_PLAN_INCONSISTENT",
            build_remote_queen_home_manifest,
            DESIRED_GENERATION,
            remote_home,
            topic,
            lease,
            MATERIALS,
            capsule,
        )
    for material_values in (
        ("instructions/generic.md", QueenMaterialKindV1.QUEEN_RULES, "generic", "sha256:" + "4" * 64),
        ("skills/Worker/SKILL.md", QueenMaterialKindV1.SKILL, "queen", "sha256:" + "7" * 64),
        ("skills/teamlead/SKILL.md", QueenMaterialKindV1.SKILL, "queen", "sha256:" + "7" * 64),
    ):
        _expect_code(
            "RQ_E_PLAN_INCONSISTENT",
            QueenHomeMaterialV1,
            *material_values,
        )
    _expect_code(
        "RQ_E_PLAN_INCONSISTENT",
        QueenHomeMaterialV1,
        "instructions/generic.md",
        QueenMaterialKindV1.GENERIC_RULES,
        "generic",
        "sha256:" + "4" * 63,
    )


def test_resume_capsule_binds_authority_and_rejects_secret_schema_names():
    manifest = _manifest()
    lease = manifest.lease_binding
    changed = build_resume_capsule(
        CAPSULE_GENERATION,
        "queen-g18",
        "session-g18-2",
        AUTH_PLAN_DIGEST,
        BASELINE,
        lease,
        BUS_CURSOR_DIGEST,
        ACCOUNT_DIGEST,
        ACCEPTED_DIGESTS,
    )
    assert changed.capsule_digest != manifest.resume_capsule.capsule_digest
    for bad_digest in ("sha256:" + "0" * 63, "sha256:" + "A" * 64, "raw"):
        _expect_code(
            "RQ_E_PLAN_INCONSISTENT",
            build_resume_capsule,
            CAPSULE_GENERATION,
            "queen-g18",
            "session-g18-1",
            bad_digest,
            BASELINE,
            lease,
            BUS_CURSOR_DIGEST,
            ACCOUNT_DIGEST,
            ACCEPTED_DIGESTS,
        )
    _expect_code(
        "RQ_E_PLAN_INCONSISTENT",
        build_resume_capsule,
        CAPSULE_GENERATION,
        "queen-g18",
        "session-g18-1",
        AUTH_PLAN_DIGEST,
        BASELINE[:-1] + "G",
        lease,
        BUS_CURSOR_DIGEST,
        ACCOUNT_DIGEST,
        ACCEPTED_DIGESTS,
    )
    with pytest.raises(RemoteQueenBootstrapError) as caught:
        canonical_json_bytes({"token": "redacted-value"})
    assert "redacted-value" not in str(caught.value)
    assert all(field.name not in {"token", "secret", "password", "cookie", "credential", "stdout", "stderr", "command", "content"} for field in fields(RemoteQueenHomeApplyJournalV1))
    # Any valid authority digest is accepted; account age/classification is outside this slice.
    accepted_account = build_resume_capsule(
        CAPSULE_GENERATION,
        "queen-g18",
        "session-g18-1",
        AUTH_PLAN_DIGEST,
        BASELINE,
        lease,
        BUS_CURSOR_DIGEST,
        "sha256:" + "9" * 64,
        ACCEPTED_DIGESTS,
    )
    assert accepted_account.account_binding_sha256 == "sha256:" + "9" * 64


def test_canonical_json_rejects_casefolded_sensitive_key_variants():
    sensitive_keys = (
        "Token",
        "ToKen",
        "ſECRET",
        "Secret-Key",
        "AUTH",
        "Auth_Key",
        "Authorization",
        "Bearer",
        "Bearer-Key",
        "Bearer_Token",
        "Client_Secret",
        "PRIVATE_KEY",
        "Private-Key",
        "Body",
        "Body_Key",
        "Request_Body",
        "Response-Body",
    )

    for key in sensitive_keys:
        with pytest.raises(RemoteQueenBootstrapError) as caught:
            canonical_json_bytes({"safe": {key: "redacted-value"}})
        assert caught.value.code == "RQ_E_PLAN_INCONSISTENT"
        assert str(caught.value) == "RQ_E_PLAN_INCONSISTENT"
        assert "redacted-value" not in str(caught.value)


def test_plan_matrix_and_port_exception_redaction():
    manifest = _manifest()
    absent = _absent_snapshot(manifest)
    fake = FakeOperations([absent])
    plan = plan_remote_queen_home(manifest, fake)
    assert plan.action is QueenHomeActionV1.CREATE_HOME
    assert plan.remove_own_home_on_rollback
    assert plan.preserve_repo_on_rollback
    assert plan.preserve_vault_on_rollback
    assert plan.preserve_hive_state_on_rollback
    assert [call[0] for call in fake.calls] == ["inspect"]

    owned = _owned_snapshot(manifest)
    no_op = plan_remote_queen_home(manifest, FakeOperations([owned]))
    assert no_op.action is None
    assert not no_op.remove_own_home_on_rollback
    assert no_op.preserve_repo_on_rollback

    foreign = QueenHomeSnapshotV1(
        QueenHomeFactV1(
            QueenHomeStateKindV1.FOREIGN,
            "other-generation",
            "other-principal",
            "other-lease",
            "/home/queen/.codex-agents/Queens/G18-other-lease",
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        ),
        None,
        None,
        None,
        (),
        True,
        manifest.lease_binding.binding_digest,
        True,
        manifest.resume_capsule.bus_cursor_sha256,
        True,
        manifest.resume_capsule.account_binding_sha256,
    )
    _expect_code("RQ_E_FOREIGN_STATE", plan_remote_queen_home, manifest, FakeOperations([foreign]))
    _expect_code(
        "RQ_E_BUS_TOPIC_CONFLICT",
        plan_remote_queen_home,
        manifest,
        FakeOperations([_owned_snapshot(manifest, active_topic_principal_id="other")]),
    )
    _expect_code(
        "RQ_E_BUS_TOPIC_CONFLICT",
        plan_remote_queen_home,
        manifest,
        FakeOperations([_absent_snapshot(manifest, conflicting_write_paths=("G18/plan/**",))]),
    )
    _expect_code(
        "RQ_E_BUS_UNAVAILABLE",
        plan_remote_queen_home,
        manifest,
        FakeOperations([_absent_snapshot(manifest, bus_available=False, observed_bus_cursor_sha256=None)]),
    )
    _expect_code(
        "RQ_E_RESUME_STALE",
        plan_remote_queen_home,
        manifest,
        FakeOperations([_absent_snapshot(manifest, lease_active=False, observed_lease_binding_digest=None)]),
    )
    _expect_code(
        "RQ_E_RESUME_STALE",
        plan_remote_queen_home,
        manifest,
        FakeOperations([_absent_snapshot(manifest, observed_bus_cursor_sha256="sha256:" + "e" * 64)]),
    )
    _expect_code(
        "RQ_E_ACCOUNT_UNAVAILABLE",
        plan_remote_queen_home,
        manifest,
        FakeOperations([_absent_snapshot(manifest, account_available=False, observed_account_binding_sha256=None)]),
    )
    _expect_code(
        "RQ_E_RESUME_STALE",
        plan_remote_queen_home,
        manifest,
        FakeOperations([_owned_snapshot(manifest, home=replace(_owned_snapshot(manifest).home, baseline_commit="f" * 40))]),
    )
    _expect_code(
        "RQ_E_RESUME_STALE",
        plan_remote_queen_home,
        manifest,
        FakeOperations([RuntimeError("redacted-value")]),
    )


def test_absent_home_rejects_every_nonempty_active_topic_before_resume_checks():
    manifest = _manifest()
    snapshots = (
        _absent_snapshot(
            manifest,
            active_topic_principal_id=manifest.lease_binding.owner_principal_id,
            active_topic_home_path=manifest.home_path,
            active_topic_lease_id=manifest.lease_binding.lease_id,
            lease_active=False,
            observed_lease_binding_digest=None,
            observed_bus_cursor_sha256="sha256:" + "e" * 64,
        ),
        _absent_snapshot(
            manifest,
            active_topic_principal_id="foreign-principal",
            active_topic_home_path="/home/foreign/.codex-agents/Queens/G18-foreign",
            active_topic_lease_id="foreign-lease",
            lease_active=False,
            observed_lease_binding_digest=None,
            observed_bus_cursor_sha256="sha256:" + "e" * 64,
        ),
        _partial_active_absent_snapshot(manifest),
    )

    for snapshot in snapshots:
        operations = FakeOperations([snapshot])
        _expect_code(
            "RQ_E_BUS_TOPIC_CONFLICT",
            plan_remote_queen_home,
            manifest,
            operations,
        )
        assert [call[0] for call in operations.calls] == ["inspect"]


def test_apply_verify_rollback_call_contract_and_drift_gates():
    manifest = _manifest()
    before = _absent_snapshot(manifest)
    create_plan = plan_remote_queen_home(manifest, FakeOperations([before]))
    owned = _owned_snapshot(manifest)
    journal = RemoteQueenHomeApplyJournalV1(
        create_plan.before_digest,
        manifest.desired_generation.generation,
        manifest.home_path,
        queen_home_snapshot_digest(owned),
    )
    apply_fake = FakeOperations([before, owned], journal)
    applied = apply_remote_queen_home(ApplyRemoteQueenHomeRequestV1(create_plan, create_plan.plan_digest), apply_fake)
    assert applied.changed
    assert applied.snapshot == owned
    assert applied.journal == journal
    assert [call[0] for call in apply_fake.calls] == ["inspect", "materialize_home", "inspect"]

    no_op_plan = plan_remote_queen_home(manifest, FakeOperations([owned]))
    no_op_fake = FakeOperations([])
    no_op_result = apply_remote_queen_home(ApplyRemoteQueenHomeRequestV1(no_op_plan, no_op_plan.plan_digest), no_op_fake)
    assert not no_op_result.changed
    assert no_op_result.snapshot == owned
    assert no_op_result.journal is None
    assert no_op_fake.calls == []

    drift_fake = FakeOperations([QueenHomeSnapshotV1(
        before.home,
        before.active_topic_principal_id,
        before.active_topic_home_path,
        before.active_topic_lease_id,
        before.conflicting_write_paths,
        before.lease_active,
        before.observed_lease_binding_digest,
        before.bus_available,
        before.observed_bus_cursor_sha256,
        before.account_available,
        before.observed_account_binding_sha256,
    )])
    # A request digest mutation is rejected before any port call.
    _expect_code(
        "RQ_E_PLAN_INCONSISTENT",
        apply_remote_queen_home,
        ApplyRemoteQueenHomeRequestV1(create_plan, "sha256:" + "0" * 64),
        drift_fake,
    )
    assert drift_fake.calls == []

    verify_fake = FakeOperations([owned])
    verified = verify_remote_queen_home(VerifyRemoteQueenHomeRequestV1(no_op_plan, no_op_plan.plan_digest), verify_fake)
    assert verified.verified and verified.snapshot == owned
    assert [call[0] for call in verify_fake.calls] == ["inspect"]
    _expect_code(
        "RQ_E_RESUME_STALE",
        verify_remote_queen_home,
        VerifyRemoteQueenHomeRequestV1(no_op_plan, no_op_plan.plan_digest),
        FakeOperations([before]),
    )

    rollback_fake = FakeOperations([owned, before])
    rollback_result = rollback_remote_queen_home(
        RollbackRemoteQueenHomeRequestV1(create_plan, create_plan.plan_digest, journal),
        rollback_fake,
    )
    assert rollback_result.changed and rollback_result.snapshot == before
    assert [call[0] for call in rollback_fake.calls] == ["inspect", "rollback_home", "inspect"]

    rollback_noop_fake = FakeOperations([])
    rollback_noop_result = rollback_remote_queen_home(
        RollbackRemoteQueenHomeRequestV1(no_op_plan, no_op_plan.plan_digest, None),
        rollback_noop_fake,
    )
    assert not rollback_noop_result.changed and rollback_noop_result.snapshot == owned
    assert rollback_noop_fake.calls == []
    _expect_code(
        "RQ_E_ROLLBACK_DRIFT",
        rollback_remote_queen_home,
        RollbackRemoteQueenHomeRequestV1(create_plan, create_plan.plan_digest, None),
        FakeOperations([]),
    )
    bad_journal = replace(journal, resulting_snapshot_digest="sha256:" + "0" * 64)
    _expect_code(
        "RQ_E_ROLLBACK_DRIFT",
        rollback_remote_queen_home,
        RollbackRemoteQueenHomeRequestV1(create_plan, create_plan.plan_digest, bad_journal),
        FakeOperations([owned]),
    )


def _assert_allowed_imports(source):
    tree = ast.parse(source)
    allowed_imports = {"hashlib", "json", "re"}
    allowed_import_from = {
        "dataclasses": {"dataclass", "fields"},
        "enum": {"Enum"},
        "pathlib": {"PurePosixPath"},
        "typing": {"Protocol"},
        "codex_master.remote_queen_bootstrap": {
            "ManifestGenerationV1",
            "RemoteQueenBootstrapError",
        },
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            assert all(alias.name in allowed_imports and alias.asname is None for alias in node.names)
        if isinstance(node, ast.ImportFrom):
            assert node.level == 0
            assert node.module in allowed_import_from
            assert all(
                alias.name in allowed_import_from[node.module] and alias.asname is None
                for alias in node.names
            )


def test_ast_import_gate_rejects_qualified_unapproved_project_importfrom():
    source = "from codex_master.remote_queen_mcp import RemoteMcpFactV1"
    with pytest.raises(AssertionError):
        _assert_allowed_imports(source)


def test_production_ast_has_only_allowed_dependencies_and_no_effect_calls():
    source_path = Path(__file__).parents[1] / "src" / "codex_master" / "remote_queen_home.py"
    source = source_path.read_text(encoding="utf-8")
    tree = ast.parse(source)
    forbidden = {
        "open",
        "exec",
        "eval",
        "compile",
        "__import__",
        "import_module",
        "Path",
        "connect",
        "send",
        "receive",
    }
    _assert_allowed_imports(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            assert node.id not in forbidden
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            assert node.func.id not in forbidden
    assert "codex_master.remote_queen_mcp" not in source
    assert "codex_master.queen_runtime" not in source
    assert "codex_master.worker_resume" not in source
