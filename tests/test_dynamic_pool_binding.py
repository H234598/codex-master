"""D69 contracts for the immutable dynamic PoolAuthorityV2 binding."""

import ast
from dataclasses import FrozenInstanceError
from datetime import datetime, timezone
from pathlib import Path

import pytest

from the_hive.admission import (
    AdmissionRecord,
    AdmissionPriority,
    AdmissionStore,
    LeaseBinding,
    ResourceBinding,
    ScopeBinding,
    create_admission,
)
from the_hive.admission_runtime import (
    ADMISSION_RUNTIME_GATES,
    RuntimeGateDecision,
    ServerAdmissionRuntime,
)
from the_hive.dynamic_pool import (
    AccountPoolBindingV1,
    DynamicPoolBindingError,
    DynamicPoolInventoryV1,
    DynamicPoolInventoryEntryV1,
    exact_pool_authority_revalidation,
    resolve_dynamic_pool_selection,
)
from the_hive.hive.dispatch import (
    HiveDispatchError,
    plan_queen_assignment_from_selection,
)
from the_hive.hive.principals import (
    Principal,
    PrincipalError,
    PrincipalRegistry,
    execution_binding_from_admission,
)
from the_hive.hive.state import HiveStateStore
from the_hive.selection import (
    ModelRole,
    SelectionBand,
    SelectionCandidate,
    SelectionPolicy,
    SelectionResult,
    TaskKind,
    preview_selection,
)
from the_hive.selection_service import SelectionService
from the_hive.usage_snapshot import PoolAuthorityV2, UsageEvidenceV2


NOW = datetime(2026, 9, 14, 12, tzinfo=timezone.utc)


def binding(*, runtime_provider: str | None = "openai_chatgpt") -> AccountPoolBindingV1:
    resolved = resolve_dynamic_pool_selection(
        SelectionResult("agent-one", "gpt-primary", SelectionBand.SP3, 0),
        inventory(runtime_provider=runtime_provider),
    )
    assert isinstance(resolved.account_pool_binding, AccountPoolBindingV1)
    return resolved.account_pool_binding


def inventory(
    *, runtime_provider: str | None = "openai_chatgpt"
) -> DynamicPoolInventoryV1:
    return DynamicPoolInventoryV1(
        {
            "agent-one": DynamicPoolInventoryEntryV1(
                account_id="account-one",
                pool_id="dynamic-pool",
                authority_provider="openai",
                runtime_provider=runtime_provider,
            ),
        }
    )


def evidence(
    *,
    status: str = "complete",
    authority_provider: str = "openai",
    hive_available: bool = True,
) -> UsageEvidenceV2:
    return UsageEvidenceV2(
        accounts=(),
        status=status,  # type: ignore[arg-type]
        captured_at=NOW,
        generated_at=NOW,
        pool_authorities=(
            PoolAuthorityV2(
                account_id="account-one",
                pool_id="dynamic-pool",
                provider=authority_provider,
                allowed_lifecycles=("persistent",),
                allowed_model_families=("gpt-primary",),
                hive_available=hive_available,
                persistent_leadership_eligible=True,
                long_running_leadership_eligible=True,
                reasoning_minimum="low",
                reasoning_maximum="high",
            ),
        ),
    )


def admission(pool_binding: AccountPoolBindingV1 | None) -> AdmissionRecord:
    return create_admission(
        admission_id="adm-d69",
        request_id="req-d69",
        dispatch_id="dispatch-d69",
        workpackage_id="workpackage-d69",
        assignment_intent_id="intent-d69",
        repo_id="codex-master",
        principal_id="specialist-one",
        parent_principal_id="teamlead-one",
        grant_id="grant-d69",
        grant_digest="sha256:grant-d69",
        work_item_version=1,
        scope=ScopeBinding("write", ("src",), "sha256:scope-d69"),
        resource=ResourceBinding(
            "agent-one", "account-key", "standard", "gpt-primary", 1, pool_binding
        ),
        lease_context=LeaseBinding("claimed", "lease-d69"),
        priority=AdmissionPriority("DP1", "selection"),
        now=NOW,
    )


def queen_workpackage() -> dict[str, object]:
    return {
        "workpackage_id": "workpackage-d69",
        "repo_id": "codex-master",
        "teamlead_principal_id": "teamlead-one",
        "specialist_principal_id": "specialist-one",
        "writer_class_id": "spezialistin",
        "agent_id": "agent-one",
        "account_key": "account-key",
        "model_id": "gpt-primary",
        "model_role": "primary",
        "task_complexity": "complex",
        "scope": ("src",),
        "write_paths": ("src/task.py",),
        "mode": "enforced",
        "pilot_enabled": True,
        "account_confirmed": True,
        "authority_verified": True,
        "repository_verified": True,
        "scope_verified": True,
        "lease_available": True,
        "selection_band": "none",
    }


def test_resolver_rejects_missing_explicit_inventory_binding() -> None:
    selection = preview_selection(
        (
            SelectionCandidate(
                "agent-one",
                "account-key",
                "gpt-primary",
                TaskKind.SIMPLE,
                ModelRole.PRIMARY,
            ),
        ),
        policy=SelectionPolicy(sp3=True),
        now=NOW,
    ).selected

    assert selection is not None
    with pytest.raises(DynamicPoolBindingError, match="dynamic_pool_binding_missing"):
        resolve_dynamic_pool_selection(selection, DynamicPoolInventoryV1({}))


def test_binding_is_normal_frozen_value_and_keeps_runtime_provider_separate() -> None:
    selected = binding()

    assert selected.authority_provider == "openai"
    assert selected.runtime_provider == "openai_chatgpt"
    with pytest.raises(FrozenInstanceError):
        selected.pool_id = "other-pool"  # type: ignore[misc]


def test_exact_revalidation_requires_an_explicit_reader_without_a_fallback() -> None:
    """A product binding cannot silently read an ambient authority snapshot."""

    with pytest.raises(TypeError):
        exact_pool_authority_revalidation(binding())

    assert exact_pool_authority_revalidation(binding(), reader=None) is False  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("status", "authority_provider"),
    (
        ("unknown", "openai"),
        ("stale", "openai"),
        ("complete", "other-provider"),
    ),
)
def test_fresh_reader_rejects_unknown_stale_and_exact_provider_mismatch(
    status: str, authority_provider: str
) -> None:
    assert (
        exact_pool_authority_revalidation(
            binding(),
            reader=lambda: evidence(
                status=status, authority_provider=authority_provider
            ),
        )
        is False
    )


def test_fresh_reader_rejects_an_exact_but_unavailable_pool_authority() -> None:
    """An exact triple is not executable while its Hive availability is false."""

    assert exact_pool_authority_revalidation(
        binding(), reader=lambda: evidence(hive_available=False)
    ) is False


def test_resolver_selects_only_the_explicit_injected_inventory_entry() -> None:
    selected = preview_selection(
        (
            SelectionCandidate(
                "agent-one",
                "account-key",
                "gpt-primary",
                TaskKind.SIMPLE,
                ModelRole.PRIMARY,
            ),
        ),
        policy=SelectionPolicy(sp3=True),
        now=NOW,
    ).selected
    assert selected is not None
    injected = DynamicPoolInventoryEntryV1(
        account_id="account-one",
        pool_id="dynamic-pool",
        authority_provider="openai",
    )

    resolved = resolve_dynamic_pool_selection(
        selected, DynamicPoolInventoryV1({"agent-one": injected})
    )

    assert resolved.account_pool_binding == AccountPoolBindingV1(
        "account-one", "dynamic-pool", "openai"
    )
    with pytest.raises(DynamicPoolBindingError, match="dynamic_pool_binding_missing"):
        resolve_dynamic_pool_selection(
            selected, DynamicPoolInventoryV1({"other-agent": injected})
        )


def test_exact_binding_flows_from_selection_to_plan_and_admission_resource() -> None:
    selected = preview_selection(
        (
            SelectionCandidate(
                "agent-one",
                "account-key",
                "gpt-primary",
                TaskKind.SIMPLE,
                ModelRole.PRIMARY,
            ),
        ),
        policy=SelectionPolicy(sp3=True),
        now=NOW,
    ).selected
    assert selected is not None
    plan = plan_queen_assignment_from_selection(
        queen_id="queen-codex-master",
        dispatch_id="dispatch-d69",
        workpackage=queen_workpackage(),
        selection=selected,
        dynamic_inventory=inventory(),
    )

    assert plan.account_pool_binding == binding()
    assert (
        admission(plan.account_pool_binding).resource.account_pool_binding
        is plan.account_pool_binding
    )  # type: ignore[union-attr]


def test_selection_plan_adapter_rejects_a_manual_workpackage_binding() -> None:
    manual = queen_workpackage()
    manual["account_pool_binding"] = binding()
    selected = SelectionResult("agent-one", "gpt-primary", SelectionBand.SP3, 0)

    with pytest.raises(HiveDispatchError, match="manual_dynamic_pool_binding"):
        plan_queen_assignment_from_selection(
            queen_id="queen-codex-master",
            dispatch_id="dispatch-d69",
            workpackage=manual,
            selection=selected,
            dynamic_inventory=inventory(),
        )


def test_execution_binding_persists_the_exact_dynamic_pool_binding(
    tmp_path: Path,
) -> None:
    plan = plan_queen_assignment_from_selection(
        queen_id="queen-codex-master",
        dispatch_id="dispatch-d69",
        workpackage=queen_workpackage(),
        selection=SelectionResult("agent-one", "gpt-primary", SelectionBand.SP3, 0),
        dynamic_inventory=inventory(),
    )
    admitted = admission(plan.account_pool_binding)
    original = execution_binding_from_admission(
        binding_id="binding-d69",
        admission=admitted,
    )

    assert (
        original.principal_id,
        original.repo_id,
        original.dispatch_id,
        original.agent_id,
        original.account_key,
        original.model_id,
        original.lease_id,
        original.admission_id,
        original.expires_at_utc,
        original.account_pool_binding,
    ) == (
        admitted.principal_id,
        admitted.repo_id,
        admitted.dispatch_id,
        admitted.resource.agent_id,
        admitted.resource.account_key,
        admitted.resource.model_id,
        admitted.lease_context.lease_id,
        admitted.admission_id,
        admitted.expires_at_utc.isoformat(),
        plan.account_pool_binding,
    )

    registry = PrincipalRegistry(HiveStateStore(tmp_path / "hive"))
    digest = "sha256:" + "a" * 64
    registry.create(
        Principal(
            "godbee-d69", "godbee", None, "profile", "global", None, "active", digest, 1
        )
    )
    registry.create(
        Principal(
            "queen-d69",
            "queen",
            "godbee-d69",
            "profile",
            "repository",
            "codex-master",
            "active",
            digest,
            1,
        )
    )
    registry.create(
        Principal(
            "teamlead-one",
            "teamlead",
            "queen-d69",
            "profile",
            "repository",
            "codex-master",
            "active",
            digest,
            1,
        )
    )
    registry.create(
        Principal(
            "specialist-one",
            "specialist",
            "teamlead-one",
            "profile",
            "repository",
            "codex-master",
            "active",
            digest,
            1,
        )
    )
    registry.bind_execution(original)
    restored = PrincipalRegistry(
        HiveStateStore(tmp_path / "hive")
    ).get_active_execution_binding(
        "binding-d69", "specialist-one", "codex-master", now=NOW
    )

    assert restored.account_pool_binding is not None
    assert restored.account_pool_binding == plan.account_pool_binding


def test_execution_binding_forward_adapter_rejects_an_admission_without_binding() -> (
    None
):
    with pytest.raises(PrincipalError, match="dynamic_pool_binding_missing"):
        execution_binding_from_admission(
            binding_id="binding-missing", admission=admission(None)
        )


def test_fresh_revalidation_runs_before_execution_and_the_actual_callback() -> None:
    reads: list[str] = []
    callbacks: list[str] = []

    def reader() -> UsageEvidenceV2:
        reads.append("reader")
        return evidence()

    gates = {
        name: lambda _record, name=name: RuntimeGateDecision(True, f"{name}_verified")
        for name in ADMISSION_RUNTIME_GATES
    }
    runtime = ServerAdmissionRuntime(
        gates,
        execute=lambda _record, _operation: (
            callbacks.append("callback") or {"status": "ok"}
        ),
        pool_authority_reader=reader,
        now=lambda: NOW,
    )
    service = SelectionService(
        AdmissionStore(), runtime, now=lambda: NOW, sleeper=lambda _delay: None
    )

    assert service.execute_with_retry(
        lambda: admission(binding()), "hive_assignment_callback"
    )["result"] == {"status": "ok"}
    assert reads == ["reader", "reader"]
    assert callbacks == ["callback"]


def test_reserve_to_callback_authority_drift_blocks_the_callback() -> None:
    callbacks: list[str] = []
    values = iter((evidence(), evidence(hive_available=False)))
    gates = {
        name: lambda _record, name=name: RuntimeGateDecision(True, f"{name}_verified")
        for name in ADMISSION_RUNTIME_GATES
    }
    runtime = ServerAdmissionRuntime(
        gates,
        execute=lambda _record, _operation: (
            callbacks.append("callback") or {"status": "unexpected"}
        ),
        pool_authority_reader=lambda: next(values),
        now=lambda: NOW,
    )
    service = SelectionService(
        AdmissionStore(), runtime, now=lambda: NOW, sleeper=lambda _delay: None
    )

    with pytest.raises(RuntimeError, match="pool_authority_revalidation_denied"):
        service.execute_with_retry(
            lambda: admission(binding()), "hive_assignment_callback"
        )
    assert callbacks == []


def _structural_binding_issuer_sites(
    sources: dict[str, str],
) -> dict[str, set[str]]:
    def dotted_name(node: ast.expr) -> str | None:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            parent = dotted_name(node.value)
            return f"{parent}.{node.attr}" if parent is not None else None
        return None

    def literal_text(node: ast.expr) -> str | None:
        return (
            node.value
            if isinstance(node, ast.Constant) and isinstance(node.value, str)
            else None
        )

    def imported_dynamic_pool(
        node: ast.expr,
        *,
        module_paths: set[str],
        root_module_names: set[str],
        import_module_names: set[str],
        importlib_module_names: set[str],
    ) -> bool:
        if dotted_name(node) in module_paths:
            return True
        if not isinstance(node, ast.Call):
            return False
        if (
            isinstance(node.func, ast.Name)
            and node.func.id == "getattr"
            and len(node.args) >= 2
            and dotted_name(node.args[0]) in root_module_names
            and literal_text(node.args[1]) == "dynamic_pool"
        ):
            return True
        if (
            isinstance(node.func, ast.Name)
            and node.func.id == "__import__"
            and node.args
            and literal_text(node.args[0]) == "the_hive.dynamic_pool"
        ):
            return True
        if (
            isinstance(node.func, ast.Name)
            and node.func.id in import_module_names
            and node.args
            and literal_text(node.args[0]) == "the_hive.dynamic_pool"
        ):
            return True
        return (
            isinstance(node.func, ast.Attribute)
            and node.func.attr == "import_module"
            and dotted_name(node.func.value) in importlib_module_names
            and node.args
            and literal_text(node.args[0]) == "the_hive.dynamic_pool"
        )

    sites = {"raw": set(), "factory": set(), "opaque": set()}
    for relative, source in sorted(sources.items()):
        tree = ast.parse(source, filename=relative)
        constructor_names = {"AccountPoolBindingV1"}
        factory_names = {"_make_account_pool_binding_v1"}
        module_paths = {"the_hive.dynamic_pool"}
        root_module_names: set[str] = set()
        import_module_names: set[str] = set()
        importlib_module_names: set[str] = set()
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.ImportFrom)
                and node.module == "the_hive.dynamic_pool"
            ):
                for imported in node.names:
                    if imported.name == "AccountPoolBindingV1":
                        constructor_names.add(imported.asname or imported.name)
                    if imported.name == "_make_account_pool_binding_v1":
                        factory_names.add(imported.asname or imported.name)
                    if imported.name == "*":
                        sites["opaque"].add(f"{relative}:{node.lineno}")
            elif isinstance(node, ast.Import):
                for imported in node.names:
                    if imported.name == "the_hive.dynamic_pool":
                        if imported.asname is None:
                            root_module_names.add("the_hive")
                        else:
                            module_paths.add(imported.asname)
                    elif imported.name == "the_hive":
                        root_module_names.add(imported.asname or imported.name)
                    elif imported.name == "importlib":
                        importlib_module_names.add(imported.asname or imported.name)
            elif isinstance(node, ast.ImportFrom) and node.module == "the_hive":
                for imported in node.names:
                    if imported.name == "dynamic_pool":
                        module_paths.add(imported.asname or imported.name)
            elif isinstance(node, ast.ImportFrom) and node.module == "importlib":
                for imported in node.names:
                    if imported.name == "import_module":
                        import_module_names.add(imported.asname or imported.name)
        module_paths.update(f"{name}.dynamic_pool" for name in root_module_names)

        def dynamic_module_attribute(value: ast.expr, attribute: str) -> bool:
            return (
                isinstance(value, ast.Attribute)
                and value.attr == attribute
                and imported_dynamic_pool(
                    value.value,
                    module_paths=module_paths,
                    root_module_names=root_module_names,
                    import_module_names=import_module_names,
                    importlib_module_names=importlib_module_names,
                )
            )

        def dynamic_module_getattr(value: ast.expr, attribute: str) -> bool:
            return (
                isinstance(value, ast.Call)
                and isinstance(value.func, ast.Name)
                and value.func.id == "getattr"
                and len(value.args) >= 2
                and imported_dynamic_pool(
                    value.args[0],
                    module_paths=module_paths,
                    root_module_names=root_module_names,
                    import_module_names=import_module_names,
                    importlib_module_names=importlib_module_names,
                )
                and literal_text(value.args[1]) == attribute
            )

        def opaque_dynamic_getattr(value: ast.expr) -> bool:
            return (
                isinstance(value, ast.Call)
                and isinstance(value.func, ast.Name)
                and value.func.id == "getattr"
                and len(value.args) >= 2
                and imported_dynamic_pool(
                    value.args[0],
                    module_paths=module_paths,
                    root_module_names=root_module_names,
                    import_module_names=import_module_names,
                    importlib_module_names=importlib_module_names,
                )
                and literal_text(value.args[1]) is None
            )

        assignments = tuple(
            node
            for node in ast.walk(tree)
            if isinstance(node, (ast.Assign, ast.AnnAssign))
        )
        aliases_changed = True
        while aliases_changed:
            aliases_changed = False
            for node in assignments:
                value = node.value
                targets = (
                    node.targets if isinstance(node, ast.Assign) else (node.target,)
                )
                if value is None:
                    continue
                if opaque_dynamic_getattr(value):
                    sites["opaque"].add(f"{relative}:{node.lineno}")
                is_constructor = (
                    (isinstance(value, ast.Name) and value.id in constructor_names)
                    or dynamic_module_attribute(value, "AccountPoolBindingV1")
                    or dynamic_module_getattr(value, "AccountPoolBindingV1")
                )
                is_factory = (
                    (isinstance(value, ast.Name) and value.id in factory_names)
                    or dynamic_module_attribute(value, "_make_account_pool_binding_v1")
                    or dynamic_module_getattr(value, "_make_account_pool_binding_v1")
                )
                for target in targets:
                    if not isinstance(target, ast.Name):
                        continue
                    if is_constructor and target.id not in constructor_names:
                        constructor_names.add(target.id)
                        aliases_changed = True
                    if is_factory and target.id not in factory_names:
                        factory_names.add(target.id)
                        aliases_changed = True
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            direct = (
                isinstance(node.func, ast.Name) and node.func.id in constructor_names
            )
            module_attribute = (
                isinstance(node.func, ast.Attribute)
                and node.func.attr == "AccountPoolBindingV1"
                and imported_dynamic_pool(
                    node.func.value,
                    module_paths=module_paths,
                    root_module_names=root_module_names,
                    import_module_names=import_module_names,
                    importlib_module_names=importlib_module_names,
                )
            )
            deferred_getattr = (
                isinstance(node.func, ast.Call)
                and isinstance(node.func.func, ast.Name)
                and node.func.func.id == "getattr"
                and len(node.func.args) >= 2
                and imported_dynamic_pool(
                    node.func.args[0],
                    module_paths=module_paths,
                    root_module_names=root_module_names,
                    import_module_names=import_module_names,
                    importlib_module_names=importlib_module_names,
                )
                and literal_text(node.func.args[1]) == "AccountPoolBindingV1"
            )
            if direct or module_attribute or deferred_getattr:
                sites["raw"].add(f"{relative}:{node.lineno}")
            factory_direct = (
                isinstance(node.func, ast.Name) and node.func.id in factory_names
            )
            factory_attribute = (
                isinstance(node.func, ast.Attribute)
                and node.func.attr == "_make_account_pool_binding_v1"
                and imported_dynamic_pool(
                    node.func.value,
                    module_paths=module_paths,
                    root_module_names=root_module_names,
                    import_module_names=import_module_names,
                    importlib_module_names=importlib_module_names,
                )
            )
            factory_getattr = (
                isinstance(node.func, ast.Call)
                and isinstance(node.func.func, ast.Name)
                and node.func.func.id == "getattr"
                and len(node.func.args) >= 2
                and imported_dynamic_pool(
                    node.func.args[0],
                    module_paths=module_paths,
                    root_module_names=root_module_names,
                    import_module_names=import_module_names,
                    importlib_module_names=importlib_module_names,
                )
                and literal_text(node.func.args[1]) == "_make_account_pool_binding_v1"
            )
            if factory_direct or factory_attribute or factory_getattr:
                sites["factory"].add(f"{relative}:{node.lineno}")
            opaque_factory_getattr = (
                isinstance(node.func, ast.Call)
                and isinstance(node.func.func, ast.Name)
                and node.func.func.id == "getattr"
                and len(node.func.args) >= 2
                and imported_dynamic_pool(
                    node.func.args[0],
                    module_paths=module_paths,
                    root_module_names=root_module_names,
                    import_module_names=import_module_names,
                    importlib_module_names=importlib_module_names,
                )
                and literal_text(node.func.args[1]) is None
            )
            if opaque_factory_getattr:
                sites["opaque"].add(f"{relative}:{node.lineno}")
    return sites


def test_static_allowlist_rejects_actual_factory_bypass_forms() -> None:
    root = Path(__file__).resolve().parents[1]
    fixture = "tests/fixtures/dynamic_pool_static/actual_factory_bypasses.py"

    sites = _structural_binding_issuer_sites(
        {fixture: (root / fixture).read_text(encoding="utf-8")}
    )

    assert sites["raw"] == set()
    assert sites["factory"] == {
        f"{fixture}:4",
        f"{fixture}:5",
        f"{fixture}:6",
        f"{fixture}:8",
        f"{fixture}:12",
        f"{fixture}:14",
    }
    assert sites["opaque"] == {f"{fixture}:10", f"{fixture}:15"}


def test_all_candidate_product_code_allows_binding_construction_only_in_the_resolver_module() -> (
    None
):
    root = Path(__file__).resolve().parents[1]
    sources = {
        path.relative_to(root).as_posix(): path.read_text(encoding="utf-8")
        for path in sorted((root / "src").rglob("*.py"))
    }

    sites = _structural_binding_issuer_sites(sources)

    assert sites["raw"] == {"src/the_hive/dynamic_pool.py:72"}
    assert sites["factory"] == {
        "src/the_hive/dynamic_pool.py:102",
        "src/the_hive/dynamic_pool.py:120",
        "src/the_hive/dynamic_pool.py:177",
    }
    assert sites["opaque"] == set()
