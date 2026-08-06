from pathlib import Path

import pytest

from codex_master.hive.principals import (
    ExecutionBinding,
    Principal,
    PrincipalError,
    PrincipalRegistry,
)
from codex_master.hive.state import HiveStateStore


DIGEST = "sha256:" + "a" * 64


def principal(principal_id: str, class_id: str, parent: str | None, repo: str | None):
    scope = "global" if repo is None else "repository"
    return Principal(principal_id, class_id, parent, "profile", scope, repo, "active", DIGEST, 1)


def chain(registry: PrincipalRegistry) -> None:
    registry.create(principal("godbee-main", "gottbiene", None, None))
    registry.create(principal("queen-repo", "koenigin", "godbee-main", "repo-one"))
    registry.create(principal("lead-one", "teamleiterin", "queen-repo", "repo-one"))


def binding(binding_id: str = "bind-one") -> ExecutionBinding:
    return ExecutionBinding(
        binding_id, "lead-one", "repo-one", "dispatch-one", "a1", "private-account",
        "gpt-primary", "lease-one", "adm-one", "active", "2026-08-06T12:01:00Z",
    )


def test_parent_chain_and_repository_scope_are_enforced() -> None:
    registry = PrincipalRegistry()
    chain(registry)
    with pytest.raises(PrincipalError, match="root_principal_has_parent"):
        registry.create(principal("bad-root", "gottbiene", "godbee-main", None))
    with pytest.raises(PrincipalError, match="principal_parent_required"):
        registry.create(principal("bad-queen", "koenigin", None, "repo-one"))
    with pytest.raises(PrincipalError, match="principal_scope_mismatch"):
        registry.create(Principal("bad-queen", "koenigin", "godbee-main", "profile", "global", "repo-one", "active", DIGEST, 1))


def test_execution_binding_is_unique_and_public_view_is_private() -> None:
    registry = PrincipalRegistry()
    chain(registry)
    stored = registry.bind_execution(binding())
    assert stored.binding_id == "bind-one"
    public = registry.public_bindings()[0]
    assert "account_key" not in public
    assert "lease_id" not in public
    with pytest.raises(PrincipalError, match="duplicate_active_execution_binding"):
        registry.bind_execution(binding("bind-two"))
    assert registry.release_execution("bind-one").state == "released"


def test_registry_persists_principals_and_bindings(tmp_path: Path) -> None:
    state = HiveStateStore(tmp_path / "hive")
    first = PrincipalRegistry(state)
    chain(first)
    first.bind_execution(binding())
    second = PrincipalRegistry(state)
    assert second.get("queen-repo").repo_id == "repo-one"
    assert second.public_bindings()[0]["binding_id"] == "bind-one"


def test_retire_uses_version_cas_and_blocks_new_binding() -> None:
    registry = PrincipalRegistry()
    chain(registry)
    retired = registry.retire("lead-one", expected_version=1)
    assert retired.state == "retired"
    with pytest.raises(PrincipalError, match="principal_inactive"):
        registry.bind_execution(binding())
    with pytest.raises(PrincipalError, match="stale_principal_version"):
        registry.retire("queen-repo", expected_version=0)
