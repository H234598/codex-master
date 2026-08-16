from __future__ import annotations

from datetime import datetime, timezone, tzinfo, timedelta
from types import SimpleNamespace

import pytest

import codex_master.hive.capabilities as capabilities
from codex_master.hive.capabilities import (
    GODDESS_REPORT_AUTO_CAPABILITY,
    QUEEN_CLASSES,
    ROOT_EXECUTIVE_CLASSES,
    CapabilityError,
    requires_goddess_auto_report,
)
from codex_master.hive.principals import ExecutionBinding, Principal, PrincipalError, PrincipalRegistry


DIGEST = "sha256:" + "a" * 64
NOW = datetime(2026, 8, 15, 12, 0, tzinfo=timezone.utc)
FUTURE = "2026-08-15T12:01:00Z"
EXPIRED = "2026-08-15T11:59:59Z"
ACCOUNT_MARKER = "secret-account-marker"
LEASE_MARKER = "secret-lease-marker"
ADMISSION_MARKER = "secret-admission-marker"


def principal(
    principal_id: str,
    class_id: str,
    parent_principal_id: str | None = None,
    repo_id: str | None = None,
    *,
    state: str = "active",
) -> Principal:
    scope_kind = "global" if repo_id is None else "repository"
    return Principal(
        principal_id,
        class_id,
        parent_principal_id,
        "profile",
        scope_kind,
        repo_id,
        state,
        DIGEST,
        1,
    )


def binding(
    binding_id: str,
    principal_id: str,
    *,
    repo_id: str | None = None,
    state: str = "active",
    expires_at_utc: str = FUTURE,
) -> ExecutionBinding:
    return ExecutionBinding(
        binding_id,
        principal_id,
        repo_id,
        f"dispatch-{binding_id}",
        f"agent-{binding_id}",
        ACCOUNT_MARKER,
        "model-primary",
        LEASE_MARKER,
        ADMISSION_MARKER,
        state,
        expires_at_utc,
    )


def registry_with_root(class_id: str = "goettin") -> PrincipalRegistry:
    registry = PrincipalRegistry()
    registry.create(principal(f"{class_id}-root", class_id))
    return registry


def test_constants_and_import_surface_are_exact() -> None:
    assert ROOT_EXECUTIVE_CLASSES == frozenset({"gottbiene", "godbee", "goettin", "goddess"})
    assert QUEEN_CLASSES == frozenset({"koenigin", "queen"})
    assert GODDESS_REPORT_AUTO_CAPABILITY == "goddess.report.auto"
    assert capabilities.__all__ == [
        "CapabilityError",
        "GODDESS_REPORT_AUTO_CAPABILITY",
        "QUEEN_CLASSES",
        "ROOT_EXECUTIVE_CLASSES",
        "requires_goddess_auto_report",
    ]
    assert not hasattr(capabilities, "Principal")
    assert not hasattr(capabilities, "PrincipalRegistry")


@pytest.mark.parametrize("root_class", sorted(ROOT_EXECUTIVE_CLASSES))
@pytest.mark.parametrize("queen_class", sorted(QUEEN_CLASSES))
def test_all_canonical_roots_accept_queens_without_changing_old_hierarchy(
    root_class: str,
    queen_class: str,
) -> None:
    registry = PrincipalRegistry()
    root_id = f"{root_class}-root"
    registry.create(principal(root_id, root_class))
    queen = principal(f"{queen_class}-child", queen_class, root_id, "repo-one")
    registry.create(queen)
    assert registry.get(queen.principal_id) == queen


@pytest.mark.parametrize("root_class", sorted(ROOT_EXECUTIVE_CLASSES))
def test_active_root_with_capability_and_own_unexpired_binding_is_eligible(root_class: str) -> None:
    registry = registry_with_root(root_class)
    root_id = f"{root_class}-root"
    registry.bind_execution(binding("binding-own", root_id))
    assert requires_goddess_auto_report(
        registry.get(root_id),
        capabilities=frozenset({GODDESS_REPORT_AUTO_CAPABILITY}),
        registry=registry,
        now=NOW,
    ) is True


def test_truth_table_denies_missing_released_expired_foreign_and_nonroot_bindings() -> None:
    registry = PrincipalRegistry()
    registry.create(principal("goettin-root", "goettin"))
    registry.create(principal("goddess-root", "goddess"))
    registry.create(principal("queen-child", "queen", "goettin-root", "repo-one"))
    capability = frozenset({GODDESS_REPORT_AUTO_CAPABILITY})
    root = registry.get("goettin-root")

    assert requires_goddess_auto_report(root, capabilities=capability, registry=registry, now=NOW) is False
    registry.bind_execution(binding("binding-expired", "goettin-root", expires_at_utc=EXPIRED))
    assert requires_goddess_auto_report(root, capabilities=capability, registry=registry, now=NOW) is False
    registry.bind_execution(binding("binding-foreign", "goddess-root"))
    assert requires_goddess_auto_report(root, capabilities=capability, registry=registry, now=NOW) is False
    registry.bind_execution(binding("binding-released", "goettin-root"))
    registry.release_execution("binding-released")
    assert requires_goddess_auto_report(root, capabilities=capability, registry=registry, now=NOW) is False

    queen = registry.get("queen-child")
    registry.bind_execution(binding("binding-queen", "queen-child", repo_id="repo-one"))
    assert requires_goddess_auto_report(queen, capabilities=capability, registry=registry, now=NOW) is False


def test_expiry_equality_is_not_active_and_active_plus_expired_is_true() -> None:
    registry = registry_with_root()
    root = registry.get("goettin-root")
    capability = frozenset({GODDESS_REPORT_AUTO_CAPABILITY})
    registry.bind_execution(binding("binding-equal", root.principal_id, expires_at_utc=NOW.isoformat().replace("+00:00", "Z")))
    assert registry.has_active_execution_binding(root.principal_id, now=NOW) is False
    registry.bind_execution(binding("binding-active", root.principal_id))
    assert requires_goddess_auto_report(root, capabilities=capability, registry=registry, now=NOW) is True


def test_multiple_binding_order_has_same_boolean_result() -> None:
    outcomes: list[bool] = []
    for binding_ids in (("binding-expired", "binding-active"), ("binding-active", "binding-expired")):
        registry = registry_with_root()
        root = registry.get("goettin-root")
        for binding_id in binding_ids:
            registry.bind_execution(
                binding(
                    binding_id,
                    root.principal_id,
                    expires_at_utc=EXPIRED if binding_id.endswith("expired") else FUTURE,
                )
            )
        outcomes.append(
            requires_goddess_auto_report(
                root,
                capabilities=frozenset({GODDESS_REPORT_AUTO_CAPABILITY}),
                registry=registry,
                now=NOW,
            )
        )
    assert outcomes == [True, True]

    expired_only = registry_with_root()
    root = expired_only.get("goettin-root")
    expired_only.bind_execution(binding("binding-expired-one", root.principal_id, expires_at_utc=EXPIRED))
    expired_only.bind_execution(binding("binding-expired-two", root.principal_id, expires_at_utc=EXPIRED))
    assert expired_only.has_active_execution_binding(root.principal_id, now=NOW) is False


def test_inactive_unknown_nonroot_and_missing_capability_are_denied() -> None:
    registry = PrincipalRegistry()
    registry.create(principal("goddess-root", "goddess", state="retired"))
    registry.create(principal("goettin-root", "goettin"))
    registry.create(principal("queen-child", "queen", "goettin-root", "repo-one"))
    registry.bind_execution(binding("binding-queen", "queen-child", repo_id="repo-one"))
    capability = frozenset({GODDESS_REPORT_AUTO_CAPABILITY})

    assert requires_goddess_auto_report(
        registry.get("goddess-root"), capabilities=capability, registry=registry, now=NOW
    ) is False
    assert requires_goddess_auto_report(
        registry.get("queen-child"), capabilities=capability, registry=registry, now=NOW
    ) is False
    assert requires_goddess_auto_report(
        registry.get("goettin-root"), capabilities=frozenset(), registry=registry, now=NOW
    ) is False
    unknown = principal("unknown-class", "unknown-class")
    assert requires_goddess_auto_report(unknown, capabilities=capability, registry=registry, now=NOW) is False


def test_authoritative_registry_identity_blocks_forged_goddess() -> None:
    registry = PrincipalRegistry()
    registry.create(principal("godbee-main", "godbee"))
    registry.create(principal("queen-repo", "queen", "godbee-main", "repo-one"))
    registry.create(principal("lead-one", "teamleiterin", "queen-repo", "repo-one"))
    registry.create(principal("specialist-one", "specialist", "lead-one", "repo-one"))
    worker = principal("worker-one", "worker", "specialist-one", "repo-one")
    registry.create(worker)
    registry.bind_execution(binding("binding-worker", worker.principal_id, repo_id="repo-one"))

    forged_goddess = principal(worker.principal_id, "goddess")
    assert requires_goddess_auto_report(
        forged_goddess,
        capabilities=frozenset({GODDESS_REPORT_AUTO_CAPABILITY}),
        registry=registry,
        now=NOW,
    ) is False


def test_additional_string_capabilities_are_allowed_but_non_strings_are_not() -> None:
    registry = registry_with_root("goddess")
    root = registry.get("goddess-root")
    registry.bind_execution(binding("binding-goddess", root.principal_id))
    assert requires_goddess_auto_report(
        root,
        capabilities=frozenset({GODDESS_REPORT_AUTO_CAPABILITY, "fleet.read_compact"}),
        registry=registry,
        now=NOW,
    ) is True
    with pytest.raises(CapabilityError):
        requires_goddess_auto_report(
            root,
            capabilities=frozenset({GODDESS_REPORT_AUTO_CAPABILITY, 7}),
            registry=registry,
            now=NOW,
        )


def test_marker_only_capability_short_circuits_without_marker_leak(monkeypatch: pytest.MonkeyPatch) -> None:
    registry = registry_with_root("goddess")
    root = registry.get("goddess-root")
    calls: list[str] = []

    def fail_query(*_args: object, **_kwargs: object) -> object:
        calls.append("queried")
        raise AssertionError("missing capability must short-circuit")

    monkeypatch.setattr(registry, "get", fail_query)
    monkeypatch.setattr(registry, "has_active_execution_binding", fail_query)
    result = requires_goddess_auto_report(
        root,
        capabilities=frozenset({ACCOUNT_MARKER}),
        registry=registry,
        now=NOW,
    )
    assert result is False
    assert calls == []
    assert ACCOUNT_MARKER not in str(result)
    assert ACCOUNT_MARKER not in repr(result)


def test_marker_plus_required_capability_remains_eligible_without_leak() -> None:
    registry = registry_with_root("goddess")
    root = registry.get("goddess-root")
    registry.bind_execution(binding("binding-goddess-marker", root.principal_id))
    result = requires_goddess_auto_report(
        root,
        capabilities=frozenset({GODDESS_REPORT_AUTO_CAPABILITY, ACCOUNT_MARKER}),
        registry=registry,
        now=NOW,
    )
    assert result is True
    assert ACCOUNT_MARKER not in str(result)
    assert ACCOUNT_MARKER not in repr(result)


class BrokenTimezone(tzinfo):
    def utcoffset(self, _value: datetime) -> timedelta:
        raise RuntimeError("secret-time-marker")


@pytest.mark.parametrize(
    "principal_value,registry_value,capabilities_value,now_value",
    [
        (SimpleNamespace(), None, frozenset({GODDESS_REPORT_AUTO_CAPABILITY}), NOW),
        (None, SimpleNamespace(), frozenset({GODDESS_REPORT_AUTO_CAPABILITY}), NOW),
        (None, None, [GODDESS_REPORT_AUTO_CAPABILITY], NOW),
        (None, None, frozenset({GODDESS_REPORT_AUTO_CAPABILITY}), datetime(2026, 8, 15, 12, 0)),
        (None, None, frozenset({GODDESS_REPORT_AUTO_CAPABILITY}), "secret-time-marker"),
        (None, None, frozenset({GODDESS_REPORT_AUTO_CAPABILITY}), datetime(2026, 8, 15, 12, 0, tzinfo=BrokenTimezone())),
    ],
)
def test_invalid_inputs_raise_marker_free_capability_errors(
    principal_value: object,
    registry_value: object,
    capabilities_value: object,
    now_value: object,
) -> None:
    registry = registry_with_root()
    root = registry.get("goettin-root")
    with pytest.raises(CapabilityError) as raised:
        requires_goddess_auto_report(
            root if principal_value is None else principal_value,
            capabilities=capabilities_value,
            registry=registry if registry_value is None else registry_value,
            now=now_value,
        )
    assert ACCOUNT_MARKER not in str(raised.value)
    assert LEASE_MARKER not in repr(raised.value)
    assert ADMISSION_MARKER not in repr(raised.value)
    assert "secret-time-marker" not in repr(raised.value)


def test_registry_query_is_private_boolean_read_only_and_marker_free(monkeypatch: pytest.MonkeyPatch) -> None:
    registry = registry_with_root()
    root = registry.get("goettin-root")
    registry.bind_execution(binding("binding-private", root.principal_id))
    principals_before = registry.list()
    bindings_before = registry.public_bindings()

    def fail_persist() -> None:
        raise AssertionError("query must not persist")

    monkeypatch.setattr(registry, "_persist", fail_persist)
    result = registry.has_active_execution_binding(root.principal_id, now=NOW)
    assert type(result) is bool
    assert result is True
    assert registry.list() == principals_before
    assert registry.public_bindings() == bindings_before
    assert ACCOUNT_MARKER not in repr(result)
    assert LEASE_MARKER not in repr(result)
    assert ADMISSION_MARKER not in repr(result)

    with pytest.raises(PrincipalError) as raised:
        registry.has_active_execution_binding("unknown-principal", now=NOW)
    assert ACCOUNT_MARKER not in str(raised.value)
    assert LEASE_MARKER not in repr(raised.value)
    assert ADMISSION_MARKER not in repr(raised.value)
