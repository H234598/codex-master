from datetime import datetime, timedelta, timezone
from pathlib import Path
import subprocess

import pytest

from codex_master.hive.authority import (
    AuthorityContext,
    AuthorityEngine,
    AuthorityError,
    AuthorityRequest,
)
from codex_master.hive.principals import Principal, PrincipalRegistry
from codex_master.hive.repositories import RepositoryBinding, RepositoryRegistry
from codex_master.hive.state import HiveStateStore


NOW = datetime(2026, 8, 6, 12, tzinfo=timezone.utc)
DIGEST = "sha256:" + "a" * 64
REQUEST_DIGEST = "sha256:" + "b" * 64


def make_repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    subprocess.run(["git", "-C", str(root), "init", "-q"], check=True)
    subprocess.run(
        ["git", "-C", str(root), "config", "remote.origin.url", "https://github.com/example/repo.git"],
        check=True,
    )
    return root


def principal(principal_id: str, class_id: str, parent: str | None, repo: str | None) -> Principal:
    return Principal(
        principal_id,
        class_id,
        parent,
        "profile",
        "global" if repo is None else "repository",
        repo,
        "active",
        DIGEST,
        1,
    )


def engine(tmp_path: Path) -> AuthorityEngine:
    state = HiveStateStore(tmp_path / "hive")
    principals = PrincipalRegistry(state)
    principals.create(principal("godbee-main", "gottbiene", None, None))
    principals.create(principal("queen-repo", "koenigin", "godbee-main", "repo-one"))
    principals.create(principal("lead-one", "teamleiterin", "queen-repo", "repo-one"))
    principals.create(principal("specialist-one", "spezialistin", "lead-one", "repo-one"))
    repositories = RepositoryRegistry(
        [RepositoryBinding("repo-one", "https://github.com/example/repo.git", make_repo(tmp_path), "main", DIGEST)]
    )
    context = AuthorityContext(
        principals,
        repositories,
        {"profile": frozenset({"hive.specialist.assign", "hive.scope.reserve", "hive.git.commit"})},
    )
    return AuthorityEngine(context, state=state, now=lambda: NOW)


def request(*, actor: str = "lead-one", capability: str = "hive.specialist.assign") -> AuthorityRequest:
    return AuthorityRequest(actor, capability, "repo-one", "dispatch-one", "wp-one", ("src",), ("src/task.py",))


def grant(engine: AuthorityEngine, *, expires: datetime | None = None):
    return engine.issue_grant(
        grant_id="grant-one",
        issuer_principal_id="lead-one",
        subject_principal_id="specialist-one",
        repo_id="repo-one",
        dispatch_id="dispatch-one",
        capabilities=("hive.specialist.assign",),
        scope=("src",),
        write_paths=("src/task.py",),
        max_delegation_depth=1,
        issued_at_utc=NOW,
        expires_at_utc=expires or NOW + timedelta(hours=1),
        nonce="nonce-one",
        request_digest=REQUEST_DIGEST,
    )


def test_public_grants_returns_redacted_grant_projection(tmp_path: Path) -> None:
    authority = engine(tmp_path)
    grant(authority)
    public = authority.public_grants()
    assert public[0]["grant_id"] == "grant-one"
    assert "nonce" not in public[0]


def test_authorize_is_deny_by_default_and_checks_scope_and_repo(tmp_path: Path) -> None:
    authority = engine(tmp_path)
    assert authority.authorize(request()).allowed is True
    assert authority.authorize(request(capability="hive.secret.read")).reason_code == "capability_denied"
    assert authority.authorize(
        AuthorityRequest("lead-one", "hive.specialist.assign", "other-repo", "dispatch-one", "wp-one", ("src",), ("src/x",))
    ).reason_code == "repository_mismatch"
    assert authority.authorize(
        AuthorityRequest("lead-one", "hive.specialist.assign", "repo-one", "dispatch-one", "wp-one", ("src",), ("tests/x",))
    ).reason_code == "scope_denied"


def test_read_only_request_allows_empty_write_paths_but_keeps_scope_required(tmp_path: Path) -> None:
    existing = engine(tmp_path)
    authority = AuthorityEngine(
        AuthorityContext(
            existing.context.principals,
            existing.context.repositories,
            {"profile": frozenset({"hive.resource.trend.read"})},
        )
    )
    read_only = AuthorityRequest(
        "lead-one",
        "hive.resource.trend.read",
        "repo-one",
        None,
        None,
        (".codex-master/resource-status",),
        (),
    )

    assert authority.authorize(read_only).public() == {
        "allowed": True,
        "reason_code": "authorized",
        "grant_id": None,
    }
    assert authority.authorize(
        AuthorityRequest("lead-one", "hive.resource.other.read", "repo-one", None, None, ("src",), ())
    ).reason_code == "capability_denied"
    assert authority.authorize(
        AuthorityRequest("lead-one", "hive.resource.trend.read", "other-repo", None, None, ("src",), ())
    ).reason_code == "repository_mismatch"
    with pytest.raises(AuthorityError, match="invalid_scope"):
        AuthorityRequest("lead-one", "hive.resource.trend.read", "repo-one", None, None, (), ())


def test_global_goettin_request_remains_scope_denied(tmp_path: Path) -> None:
    state = HiveStateStore(tmp_path / "hive")
    principals = PrincipalRegistry(state)
    principals.create(Principal("goettin-main", "goettin", None, "goddess", "global", None, "active", DIGEST, 1))
    authority = AuthorityEngine(
        AuthorityContext(principals, RepositoryRegistry(()), {"goddess": frozenset({"goddess.report.auto"})}),
        state=state,
        now=lambda: NOW,
    )
    decision = authority.authorize(
        AuthorityRequest("goettin-main", "goddess.report.auto", None, None, None, ("report",), ("report",))
    )
    assert (decision.allowed, decision.reason_code, decision.grant_id) == (False, "scope_denied", None)


def test_authority_context_three_argument_construction_remains_compatible(tmp_path: Path) -> None:
    current = engine(tmp_path).context
    assert AuthorityContext(current.principals, current.repositories, current.capabilities) == current


def test_grant_requires_parent_capability_subset_and_scope(tmp_path: Path) -> None:
    authority = engine(tmp_path)
    created = grant(authority)
    assert created.status == "active"
    assert "nonce_digest" not in created.public()
    assert "scope" not in created.public()
    with pytest.raises(AuthorityError, match="parent_mismatch"):
        authority.issue_grant(
            grant_id="grant-bad-parent", issuer_principal_id="queen-repo", subject_principal_id="specialist-one",
            repo_id="repo-one", dispatch_id="dispatch-one", capabilities=("hive.specialist.assign",),
            scope=("src",), write_paths=("src/x",), max_delegation_depth=1, issued_at_utc=NOW,
            expires_at_utc=NOW + timedelta(hours=1), nonce="nonce", request_digest=REQUEST_DIGEST,
        )
    with pytest.raises(AuthorityError, match="scope_denied"):
        authority.issue_grant(
            grant_id="grant-bad-scope", issuer_principal_id="lead-one", subject_principal_id="specialist-one",
            repo_id="repo-one", dispatch_id="dispatch-one", capabilities=("hive.specialist.assign",),
            scope=("src",), write_paths=("tests/x",), max_delegation_depth=1, issued_at_utc=NOW,
            expires_at_utc=NOW + timedelta(hours=1), nonce="nonce", request_digest=REQUEST_DIGEST,
        )


def test_consume_is_nonce_bound_request_bound_and_single_use(tmp_path: Path) -> None:
    authority = engine(tmp_path)
    grant(authority)
    assert authority.consume_grant("grant-one", "wrong", REQUEST_DIGEST).reason_code == "grant_nonce_mismatch"
    assert authority.consume_grant("grant-one", "nonce-one", "sha256:" + "c" * 64).reason_code == "grant_request_mismatch"
    consumed = authority.consume_grant("grant-one", "nonce-one", REQUEST_DIGEST)
    assert consumed.allowed is True
    assert authority.consume_grant("grant-one", "nonce-one", REQUEST_DIGEST).reason_code == "grant_replayed"


def test_file_backed_consume_reloads_under_cross_process_lock(tmp_path: Path) -> None:
    first = engine(tmp_path)
    grant(first)
    second = AuthorityEngine(first.context, state=HiveStateStore(tmp_path / "hive"), now=lambda: NOW)

    assert first.consume_grant("grant-one", "nonce-one", REQUEST_DIGEST).allowed is True
    assert second.consume_grant("grant-one", "nonce-one", REQUEST_DIGEST).reason_code == "grant_replayed"


def test_expiry_revoke_cas_and_persistence_are_fail_closed(tmp_path: Path) -> None:
    authority = engine(tmp_path)
    grant(authority, expires=NOW + timedelta(seconds=1))
    expired = AuthorityEngine(authority.context, state=HiveStateStore(tmp_path / "hive"), now=lambda: NOW + timedelta(hours=2))
    assert expired.consume_grant("grant-one", "nonce-one", REQUEST_DIGEST).reason_code == "grant_expired"
    with pytest.raises(AuthorityError, match="stale_grant_version"):
        expired.revoke_grant("grant-one", expected_version=0)
    revoked = expired.revoke_grant("grant-one", expected_version=2)
    assert revoked.status == "revoked"
    assert AuthorityEngine(authority.context, state=HiveStateStore(tmp_path / "hive"), now=lambda: NOW).get_grant("grant-one").status == "revoked"
