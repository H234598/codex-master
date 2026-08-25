import ast
import dataclasses
import importlib.util
import pickle
import sys
from pathlib import Path

import pytest

from codex_master.spark_retry import ResumeCapsuleV1


MODULE_PATH = Path(__file__).resolve().parents[1] / "src/codex_master/worker_resume.py"


def _resume_module():
    assert MODULE_PATH.is_file(), "worker_resume module is missing"
    spec = importlib.util.spec_from_file_location(
        "worker_resume_under_test", MODULE_PATH
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _digest(value: str) -> str:
    return "sha256:" + (value * 64)


def _capsule(module):
    return module.create_resume_capsule(
        bee_digest=_digest("a"),
        session_digest=_digest("b"),
        topic_digest=_digest("c"),
        policy_digest=_digest("d"),
        account_binding_digest=_digest("e"),
        capsule_revision=2,
    )


def test_persistent_or_resumable_worker_requires_topic_resume_capsule() -> None:
    module = _resume_module()
    capsule = _capsule(module)

    with pytest.raises(module.ResumeDenied):
        module.require_terminal_capsule(
            lifecycle="persistent",
            resumable=False,
            capsule=None,
            topic_digest=_digest("c"),
            policy_digest=_digest("d"),
            account_binding_digest=_digest("e"),
        )
    assert (
        module.require_terminal_capsule(
            lifecycle="persistent",
            resumable=False,
            capsule=capsule,
            topic_digest=_digest("c"),
            policy_digest=_digest("d"),
            account_binding_digest=_digest("e"),
        )
        is capsule
    )


def test_binding_lifecycle_requires_capsule_even_when_not_marked_resumable() -> None:
    module = _resume_module()

    with pytest.raises(module.ResumeDenied):
        module.require_terminal_capsule(
            lifecycle="binding",
            resumable=False,
            capsule=None,
            topic_digest=_digest("c"),
            policy_digest=_digest("d"),
            account_binding_digest=_digest("e"),
        )


def test_ephemeral_and_invocation_worker_can_finish_without_capsule() -> None:
    module = _resume_module()

    for lifecycle in ("ephemeral", "invocation"):
        assert (
            module.require_terminal_capsule(
                lifecycle=lifecycle,
                resumable=False,
                capsule=None,
                topic_digest=_digest("c"),
                policy_digest=_digest("d"),
                account_binding_digest=_digest("e"),
            )
            is None
        )


def test_capsule_binds_every_terminal_digest_and_rejects_drift() -> None:
    module = _resume_module()
    capsule = _capsule(module)

    for key in ("topic_digest", "policy_digest", "account_binding_digest"):
        expected = {
            "topic_digest": _digest("c"),
            "policy_digest": _digest("d"),
            "account_binding_digest": _digest("e"),
        }
        expected[key] = _digest("f")
        with pytest.raises(module.ResumeDenied):
            module.require_terminal_capsule(
                lifecycle="persistent", resumable=True, capsule=capsule, **expected
            )


def test_capsule_rejects_malformed_digest_and_prohibited_secret_fields() -> None:
    module = _resume_module()

    with pytest.raises(module.ResumeDenied):
        module.create_resume_capsule(
            bee_digest="bee-plain-id",
            session_digest=_digest("b"),
            topic_digest=_digest("c"),
            policy_digest=_digest("d"),
            account_binding_digest=_digest("e"),
            capsule_revision=2,
        )
    with pytest.raises(TypeError):
        module.create_resume_capsule(
            bee_digest=_digest("a"),
            session_digest=_digest("b"),
            topic_digest=_digest("c"),
            policy_digest=_digest("d"),
            account_binding_digest=_digest("e"),
            capsule_revision=2,
            profile_id="profile-private",
        )


def test_spark_resume_capsule_v1_is_not_silently_reused() -> None:
    module = _resume_module()
    v1_capsule = ResumeCapsuleV1(
        bee_id="bee-1",
        session_id="session-1",
        spark_requirement="explicit_spark",
        model="gpt-5.3",
        provider="provider",
        effort="low",
        account_binding=_digest("e"),
    )

    with pytest.raises(module.ResumeDenied):
        module.require_terminal_capsule(
            lifecycle="persistent",
            resumable=True,
            capsule=v1_capsule,
            topic_digest=_digest("c"),
            policy_digest=_digest("d"),
            account_binding_digest=_digest("e"),
        )


def test_resume_starts_new_requested_transaction_and_requires_new_lease() -> None:
    module = _resume_module()
    request = module.begin_resume_request(
        _capsule(module), new_request_id="request-after-resume"
    )

    assert request.request_id == "request-after-resume"
    assert request.phase == "REQUESTED"
    assert request.requires_new_lease is True
    assert request.allows_in_place_credential_rotation is False


def test_resume_request_is_bound_to_capsule_digests() -> None:
    module = _resume_module()
    capsule = _capsule(module)
    request = module.begin_resume_request(capsule, new_request_id="request-next")

    assert request.bee_digest == capsule.bee_digest
    assert request.session_digest == capsule.session_digest
    assert request.topic_digest == capsule.topic_digest
    assert request.policy_digest == capsule.policy_digest
    assert request.account_binding_digest == capsule.account_binding_digest


def test_resume_capsule_redacts_account_profile_and_paths() -> None:
    module = _resume_module()
    capsule = _capsule(module)

    assert repr(capsule) == "<WorkerResumeCapsuleV2 redacted>"
    assert str(capsule) == repr(capsule)
    for prohibited in ("account", "profile", "/home", "credential", "prompt"):
        assert prohibited not in repr(capsule).lower()
    assert not {
        "account_id",
        "profile_id",
        "home_path",
        "credential",
        "prompt",
    } & set(capsule.__dataclass_fields__)


def test_resume_types_are_frozen_slotted_and_not_serializable() -> None:
    module = _resume_module()
    capsule = _capsule(module)
    request = module.begin_resume_request(capsule, new_request_id="request-next")

    for value in (capsule, request):
        assert dataclasses.is_dataclass(value)
        assert hasattr(type(value), "__slots__")
        with pytest.raises(TypeError):
            pickle.dumps(value)
    with pytest.raises(dataclasses.FrozenInstanceError):
        capsule.topic_digest = _digest("f")


def test_resume_module_is_local_and_does_not_import_spark_or_runtime_boundaries() -> (
    None
):
    tree = ast.parse(MODULE_PATH.read_text(encoding="utf-8"))
    imports = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in node.names
    }
    forbidden = {
        "spark_retry",
        "server",
        "runtime_account_allocator",
        "fleet_registry",
        "fleet_home",
        "broker",
        "mcp",
        "provider",
    }

    assert not {
        name
        for name in imports
        if any(fragment in name.lower() for fragment in forbidden)
    }
