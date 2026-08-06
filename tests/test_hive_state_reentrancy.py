from datetime import datetime, timedelta, timezone
from pathlib import Path
import subprocess

from codex_master.hive.authority import AuthorityContext, AuthorityEngine
from codex_master.hive.principals import Principal, PrincipalRegistry
from codex_master.hive.repositories import RepositoryBinding, RepositoryRegistry
from codex_master.hive.state import HiveStateStore


NOW = datetime(2026, 8, 6, 12, tzinfo=timezone.utc)
DIGEST = "sha256:" + "a" * 64
REQUEST_DIGEST = "sha256:" + "b" * 64


def _repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    subprocess.run(["git", "-C", str(root), "init", "-q"], check=True)
    subprocess.run(
        ["git", "-C", str(root), "config", "remote.origin.url", "https://github.com/example/repo.git"],
        check=True,
    )
    return root


def _principal(principal_id: str, class_id: str, parent: str | None, repo_id: str | None) -> Principal:
    return Principal(
        principal_id,
        class_id,
        parent,
        "profile",
        "global" if repo_id is None else "repository",
        repo_id,
        "active",
        DIGEST,
        1,
    )


def test_persistent_authority_validation_can_reload_principal_under_nested_state_lock(tmp_path: Path) -> None:
    state = HiveStateStore(tmp_path / "hive")
    principals = PrincipalRegistry(state)
    principals.create(_principal("godbee-main", "gottbiene", None, None))
    principals.create(_principal("queen-repo", "koenigin", "godbee-main", "repo-one"))
    principals.create(_principal("lead-one", "teamleiterin", "queen-repo", "repo-one"))
    principals.create(_principal("specialist-one", "spezialistin", "lead-one", "repo-one"))
    repositories = RepositoryRegistry(
        [RepositoryBinding("repo-one", "https://github.com/example/repo.git", _repo(tmp_path), "main", DIGEST)]
    )
    authority = AuthorityEngine(
        AuthorityContext(principals, repositories, {"profile": frozenset({"hive.specialist.assign"})}),
        state=state,
        now=lambda: NOW,
    )
    authority.issue_grant(
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
        expires_at_utc=NOW + timedelta(hours=1),
        nonce="nonce-one",
        request_digest=REQUEST_DIGEST,
    )

    decision = authority.validate_grant(
        "grant-one",
        subject_principal_id="specialist-one",
        repo_id="repo-one",
        dispatch_id="dispatch-one",
        scope=("src",),
        write_paths=("src/task.py",),
        capability="hive.specialist.assign",
    )
    assert decision.allowed is True
