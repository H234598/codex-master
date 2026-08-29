from __future__ import annotations

import ast
from dataclasses import fields, replace
import importlib
import inspect
from pathlib import Path
import threading
from threading import Event, Thread

import pytest

from codex_master.dynamic_teamlead_a3_runner import RootDynamicTeamleadRunnerPermit
from codex_master.fleet_control_release_v2 import ControlReleaseSpecV2
from codex_master.fleet_runners import DynamicTeamleadRunnerPlan

from test_fleet_control_release_v2 import SPEC as V2_RELEASE
from test_fleet_root_system_bus import runner_plan, trusted_context


UNIT = "codex-master-agent@c1\\x2cc2.service"


def runner_module():
    try:
        return importlib.import_module("codex_master.dynamic_teamlead_systemd_runner")
    except Exception as exc:
        pytest.fail(f"runner module/symbol absent on P1: {type(exc).__name__}")


def permit() -> RootDynamicTeamleadRunnerPermit:
    value = object.__new__(RootDynamicTeamleadRunnerPermit)
    for name, field_value in {
        "opaque_reference": object(),
        "principal_diagnostic": "<redacted>",
        "identity_diagnostic": "<redacted>",
        "snapshot_generation": 13,
        "policy_generation": 9,
        "release_diagnostic": "<redacted>",
        "root_generation": 1,
    }.items():
        object.__setattr__(value, name, field_value)
    return value


def plan() -> DynamicTeamleadRunnerPlan:
    return runner_plan(trusted_context())


class RecordingManager:
    def __init__(
        self,
        *,
        active: object = True,
        start_result: object = None,
        start_error: Exception | None = None,
        active_error: Exception | None = None,
    ) -> None:
        self.active = active
        self.start_result = start_result
        self.start_error = start_error
        self.active_error = active_error
        self.calls: list[tuple[object, ...]] = []

    def start_unit(self, unit: str, mode: str) -> object:
        self.calls.append(("start_unit", unit, mode))
        if self.start_error is not None:
            raise self.start_error
        return self.start_result

    def unit_is_active(self, unit: str) -> object:
        self.calls.append(("unit_is_active", unit))
        if self.active_error is not None:
            raise self.active_error
        return self.active


def forged_release(schema_version: int) -> ControlReleaseSpecV2:
    value = object.__new__(ControlReleaseSpecV2)
    for field in fields(ControlReleaseSpecV2):
        object.__setattr__(value, field.name, getattr(V2_RELEASE, field.name))
    object.__setattr__(value, "schema_version", schema_version)
    return value


def assert_no_manager_call(operation, *, candidate_plan=None, candidate_permit=None) -> None:
    manager = operation.systemd
    with pytest.raises(ValueError) as caught:
        operation.execute(
            plan() if candidate_plan is None else candidate_plan,
            permit=permit() if candidate_permit is None else candidate_permit,
        )
    assert manager.calls == []
    assert r"c1\x2cc2" not in str(caught.value)
    assert "c1,c2" not in str(caught.value)
    assert "permit" not in repr(caught.value).lower()


def test_valid_exact_plan_starts_derived_unit_once_then_checks_active() -> None:
    module = runner_module()
    manager = RecordingManager()
    operation = module.RootSystemdDynamicTeamleadRunnerOperations(V2_RELEASE, manager)

    assert operation.execute(plan(), permit=permit()) is None
    assert manager.calls == [
        ("start_unit", UNIT, "fail"),
        ("unit_is_active", UNIT),
    ]


@pytest.mark.parametrize(
    ("mcs_pair", "expected_instance"),
    (("c0,c1", r"c0\x2cc1"), ("c1022,c1023", r"c1022\x2cc1023")),
)
def test_boundary_mcs_pairs_map_to_unique_reversible_instances(
    mcs_pair: str, expected_instance: str
) -> None:
    module = runner_module()
    context = trusted_context(expected_principal=replace(trusted_context().expected_principal, mcs_pair=mcs_pair))
    candidate = runner_plan(context)
    manager = RecordingManager()
    operation = module.RootSystemdDynamicTeamleadRunnerOperations(V2_RELEASE, manager)

    operation.execute(candidate, permit=permit())
    assert manager.calls[0] == (
        "start_unit",
        f"codex-master-agent@{expected_instance}.service",
        "fail",
    )
    assert manager.calls[1] == (
        "unit_is_active",
        f"codex-master-agent@{expected_instance}.service",
    )


@pytest.mark.parametrize(
    "mcs_pair",
    (
        "c01,c2",
        "c1,c01",
        "c1,c1",
        "c2,c1",
        "c-1,c2",
        "c1,c1024",
        "c1",
        "1,c2",
        "c1,c2,",
        " c1,c2",
        "c1,c2 ",
        "c1/c2",
        "c1\\c2",
        "c1.c2",
        "c1@c2",
        "c1,\x00c2",
        "c1,é",
    ),
)
def test_noncanonical_or_out_of_range_mcs_is_rejected_before_manager_call(
    mcs_pair: str,
) -> None:
    module = runner_module()
    manager = RecordingManager()
    operation = module.RootSystemdDynamicTeamleadRunnerOperations(V2_RELEASE, manager)
    candidate = replace(
        plan(),
        expected_principal=replace(plan().expected_principal, mcs_pair=mcs_pair),
    )

    assert_no_manager_call(operation, candidate_plan=candidate)


@pytest.mark.parametrize(
    "mutation",
    (
        "runtime_principal",
        "expected_principal",
        "identity_agent",
        "identity_manifest",
        "identity_mcs",
        "identity_fencing",
        "expectation_generation",
        "expectation_fencing",
        "expectation_policy",
        "expectation_projection",
        "home_principal",
        "home_policy",
        "home_projection",
        "home_mcs",
    ),
)
def test_independent_plan_binding_drift_is_rejected_before_manager_call(
    mutation: str,
) -> None:
    module = runner_module()
    manager = RecordingManager()
    operation = module.RootSystemdDynamicTeamleadRunnerOperations(V2_RELEASE, manager)
    candidate = plan()
    alternate_agent = "tl-" + "b" * 32
    alternate_digest = "e" * 64

    if mutation == "runtime_principal":
        candidate = replace(
            candidate,
            runtime_principal=replace(
                candidate.runtime_principal, principal_id=alternate_agent
            ),
        )
    elif mutation == "expected_principal":
        candidate = replace(
            candidate,
            expected_principal=replace(
                candidate.expected_principal, agent_id=alternate_agent
            ),
        )
    elif mutation == "identity_agent":
        candidate = replace(candidate, identity=replace(candidate.identity, agent_id=alternate_agent))
    elif mutation == "identity_manifest":
        candidate = replace(
            candidate,
            identity=replace(
                candidate.identity,
                manifest_generation=candidate.identity.manifest_generation + 1,
            ),
        )
    elif mutation == "identity_mcs":
        candidate = replace(candidate, identity=replace(candidate.identity, mcs_pair="c2,c3"))
    elif mutation == "identity_fencing":
        candidate = replace(
            candidate,
            identity=replace(candidate.identity, fencing_epoch=candidate.identity.fencing_epoch + 1),
        )
    elif mutation == "expectation_generation":
        candidate = replace(
            candidate,
            expectation=replace(
                candidate.expectation,
                manifest_generation=candidate.expectation.manifest_generation + 1,
            ),
        )
    elif mutation == "expectation_fencing":
        candidate = replace(
            candidate,
            expectation=replace(
                candidate.expectation,
                fencing_epoch=candidate.expectation.fencing_epoch + 1,
            ),
        )
    elif mutation == "expectation_policy":
        candidate = replace(
            candidate,
            expectation=replace(
                candidate.expectation,
                policy_generation=candidate.expectation.policy_generation + 1,
            ),
        )
    elif mutation == "expectation_projection":
        candidate = replace(
            candidate,
            expectation=replace(candidate.expectation, projection_digest=alternate_digest),
        )
    else:
        attestation = candidate.home.attestation
        binding = attestation.binding
        if mutation == "home_principal":
            binding = replace(binding, principal=replace(binding.principal, agent_id=alternate_agent))
        elif mutation == "home_policy":
            binding = replace(binding, policy=replace(binding.policy, policy_generation=10))
        elif mutation == "home_projection":
            binding = replace(binding, policy=replace(binding.policy, projection_digest=alternate_digest))
        else:
            attestation = replace(attestation, mcs_pair="c2,c3")
        candidate = replace(
            candidate,
            home=replace(candidate.home, attestation=replace(attestation, binding=binding)),
        )

    assert_no_manager_call(operation, candidate_plan=candidate)


def test_wrong_permit_type_is_rejected_before_manager_call() -> None:
    module = runner_module()
    manager = RecordingManager()
    operation = module.RootSystemdDynamicTeamleadRunnerOperations(V2_RELEASE, manager)
    assert_no_manager_call(operation, candidate_permit=object())


@pytest.mark.parametrize("release", (object(), forged_release(3)))
def test_invalid_or_mutated_v2_release_is_rejected_before_manager_call(
    release: object,
) -> None:
    module = runner_module()
    manager = RecordingManager()
    try:
        operation = module.RootSystemdDynamicTeamleadRunnerOperations(release, manager)
    except ValueError:
        assert manager.calls == []
        return
    assert_no_manager_call(operation)


@pytest.mark.parametrize(
    ("manager", "expected_calls"),
    (
        (RecordingManager(start_error=RuntimeError("private c1,c2 detail")), [("start_unit", UNIT, "fail")]),
        (RecordingManager(start_result="private c1,c2 completion"), [("start_unit", UNIT, "fail")]),
        (RecordingManager(active=False), [("start_unit", UNIT, "fail"), ("unit_is_active", UNIT)]),
        (RecordingManager(active=1), [("start_unit", UNIT, "fail"), ("unit_is_active", UNIT)]),
    ),
)
def test_manager_failure_invalid_completion_or_nonbool_inactive_state_is_terminal(
    manager: RecordingManager, expected_calls: list[tuple[object, ...]]
) -> None:
    module = runner_module()
    operation = module.RootSystemdDynamicTeamleadRunnerOperations(V2_RELEASE, manager)
    with pytest.raises(ValueError) as caught:
        operation.execute(plan(), permit=permit())
    assert manager.calls == expected_calls
    assert "private" not in str(caught.value)
    assert "c1,c2" not in str(caught.value)
    with pytest.raises(ValueError):
        operation.execute(plan(), permit=permit())
    assert manager.calls == expected_calls


def test_second_call_after_success_is_terminal_without_second_start() -> None:
    module = runner_module()
    manager = RecordingManager()
    operation = module.RootSystemdDynamicTeamleadRunnerOperations(V2_RELEASE, manager)
    operation.execute(plan(), permit=permit())
    with pytest.raises(ValueError):
        operation.execute(plan(), permit=permit())
    assert manager.calls == [("start_unit", UNIT, "fail"), ("unit_is_active", UNIT)]


def test_two_synchronized_concurrent_calls_cause_at_most_one_start() -> None:
    module = runner_module()
    started = Event()
    release = Event()

    class BlockingManager(RecordingManager):
        def start_unit(self, unit: str, mode: str) -> object:
            result = super().start_unit(unit, mode)
            started.set()
            assert release.wait(timeout=2)
            return result

    manager = BlockingManager()
    operation = module.RootSystemdDynamicTeamleadRunnerOperations(V2_RELEASE, manager)
    barrier = threading.Barrier(2)
    errors: list[Exception] = []

    def call() -> None:
        barrier.wait()
        try:
            operation.execute(plan(), permit=permit())
        except Exception as exc:
            errors.append(exc)

    threads = [Thread(target=call), Thread(target=call)]
    for thread in threads:
        thread.start()
    assert started.wait(timeout=2)
    release.set()
    for thread in threads:
        thread.join(timeout=2)
    assert all(not thread.is_alive() for thread in threads)
    assert len(errors) == 1
    assert [call for call in manager.calls if call[0] == "start_unit"] == [
        ("start_unit", UNIT, "fail")
    ]


def test_runner_private_state_is_init_disabled_and_repr_redacted() -> None:
    module = runner_module()
    operation = module.RootSystemdDynamicTeamleadRunnerOperations(V2_RELEASE, RecordingManager())
    signature = inspect.signature(module.RootSystemdDynamicTeamleadRunnerOperations)
    assert "_lock" not in signature.parameters
    assert "_terminal" not in signature.parameters
    assert repr(operation) == "<RootSystemdDynamicTeamleadRunnerOperations redacted>"
    assert "c1,c2" not in repr(operation)


def test_runner_source_has_no_live_or_process_imports() -> None:
    module = runner_module()
    source = Path(module.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    forbidden = {
        "dbus",
        "gi",
        "socket",
        "subprocess",
        "os",
        "pathlib",
        "server",
        "launcher",
        "installer",
        "environment",
        "state",
    }
    imported = {
        alias.name.split(".", 1)[0]
        for node in tree.body
        if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in node.names
    }
    assert imported.isdisjoint(forbidden)
