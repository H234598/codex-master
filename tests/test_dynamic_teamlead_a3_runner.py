from __future__ import annotations

import ast
import copy
from dataclasses import fields
import gc
import importlib
import inspect
from pathlib import Path
import pickle

import pytest


def runner_module():
    return importlib.import_module("codex_master.dynamic_teamlead_a3_runner")


def reconstructed_permit():
    permit_type = runner_module().RootDynamicTeamleadRunnerPermit
    permit = object.__new__(permit_type)
    values = {
        "opaque_reference": object(),
        "principal_diagnostic": "<redacted>",
        "identity_diagnostic": "<redacted>",
        "snapshot_generation": 13,
        "policy_generation": 9,
        "release_diagnostic": "<redacted>",
        "root_generation": 1,
    }
    for name, value in values.items():
        object.__setattr__(permit, name, value)
    return permit


def reconstructed_evidence():
    evidence_type = getattr(
        runner_module(), "RootDynamicTeamleadRunnerBindingEvidence", None
    )
    assert evidence_type is not None
    evidence = object.__new__(evidence_type)
    values = {
        "executor_identity": object(),
        "context_identity": object(),
        "snapshot_identity": object(),
        "release_identity": object(),
    }
    for name, value in values.items():
        object.__setattr__(evidence, name, value)
    return evidence


def test_runner_module_exports_only_data_permit_and_operations_protocol() -> None:
    module = runner_module()

    assert module.__all__ == (
        "DynamicTeamleadRunnerOperations",
        "RootDynamicTeamleadRunnerPermit",
        "RootDynamicTeamleadRunnerBindingEvidence",
    )
    assert inspect.isclass(module.RootDynamicTeamleadRunnerPermit)
    assert inspect.isclass(
        getattr(module, "RootDynamicTeamleadRunnerBindingEvidence", None)
    )
    assert inspect.isclass(module.DynamicTeamleadRunnerOperations)
    assert not any(
        "executor" in name.lower() and not name.startswith("_")
        for name in vars(module)
    )


def test_permit_is_data_only_redacted_and_not_constructible() -> None:
    permit_type = runner_module().RootDynamicTeamleadRunnerPermit

    with pytest.raises(TypeError):
        permit_type()

    permit = reconstructed_permit()
    assert [field.name for field in fields(permit_type)] == [
        "opaque_reference",
        "principal_diagnostic",
        "identity_diagnostic",
        "snapshot_generation",
        "policy_generation",
        "release_diagnostic",
        "root_generation",
    ]
    assert permit.principal_diagnostic == "<redacted>"
    assert permit.identity_diagnostic == "<redacted>"
    assert permit.release_diagnostic == "<redacted>"
    assert repr(permit) == "<RootDynamicTeamleadRunnerPermit redacted>"
    assert str(permit) == repr(permit)


@pytest.mark.parametrize(
    "transfer",
    (
        pytest.param(copy.copy, id="copy"),
        pytest.param(copy.deepcopy, id="deepcopy"),
        pytest.param(pickle.dumps, id="pickle"),
    ),
)
def test_permit_rejects_copy_deepcopy_and_pickle(transfer) -> None:
    with pytest.raises(TypeError):
        transfer(reconstructed_permit())


def test_permit_rejects_subclassing() -> None:
    permit_type = runner_module().RootDynamicTeamleadRunnerPermit

    with pytest.raises(TypeError):

        class ForgedPermit(permit_type):
            pass


def test_binding_evidence_is_non_transferable_data_only_and_not_attachable() -> None:
    evidence_type = runner_module().RootDynamicTeamleadRunnerBindingEvidence

    with pytest.raises(TypeError):
        evidence_type(object(), object(), object(), object())

    evidence = reconstructed_evidence()
    assert [field.name for field in fields(evidence_type)] == [
        "executor_identity",
        "context_identity",
        "snapshot_identity",
        "release_identity",
    ]
    assert repr(evidence) == "<RootDynamicTeamleadRunnerBindingEvidence redacted>"
    assert str(evidence) == repr(evidence)
    assert not hasattr(evidence, "__dict__")

    with pytest.raises(AttributeError):
        evidence.executor_identity = object()

    with pytest.raises(TypeError):

        class ForgedEvidence(evidence_type):
            pass


@pytest.mark.parametrize(
    "transfer",
    (
        pytest.param(copy.copy, id="copy"),
        pytest.param(copy.deepcopy, id="deepcopy"),
        pytest.param(pickle.dumps, id="pickle"),
    ),
)
def test_binding_evidence_rejects_copy_deepcopy_and_pickle(transfer) -> None:
    with pytest.raises(TypeError):
        transfer(reconstructed_evidence())


def test_permit_has_no_reachable_authority_or_nested_mutable_state() -> None:
    permit = reconstructed_permit()
    banned = ("issuer", "ledger", "gate", "callback", "closure", "claim", "state")

    assert all(term not in name.lower() for name in permit.__slots__ for term in banned)
    assert not hasattr(permit, "__dict__")
    for field in fields(type(permit)):
        value = getattr(permit, field.name)
        assert not callable(value)
        assert getattr(value, "__closure__", None) is None
        assert not isinstance(value, (dict, list, set, bytearray))
        assert not any(callable(item) for item in gc.get_referents(value))


def test_no_production_callable_accepts_injected_authority_capability() -> None:
    root = Path(__file__).parents[1]
    forbidden = ("ledger", "issuer", "gate", "callback", "claim")

    for relative in (
        "src/codex_master/dynamic_teamlead_a3_runner.py",
        "src/codex_master/fleet_root_system_bus.py",
    ):
        path = root / relative
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            arguments = (
                node.args.posonlyargs
                + node.args.args
                + node.args.kwonlyargs
            )
            names = [argument.arg.lower() for argument in arguments]
            assert not any(term in name for name in names for term in forbidden), (
                relative,
                node.name,
                names,
            )
