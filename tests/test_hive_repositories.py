from pathlib import Path
import subprocess

import pytest

from codex_master.hive.repositories import (
    RepositoryBinding,
    RepositoryError,
    RepositoryRegistry,
)


def make_repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    subprocess.run(["git", "-C", str(root), "init", "-q"], check=True)
    subprocess.run(
        ["git", "-C", str(root), "config", "remote.origin.url", "https://github.com/example/repo.git"],
        check=True,
    )
    return root


def registry(root: Path) -> RepositoryRegistry:
    return RepositoryRegistry(
        [
            RepositoryBinding(
                "repo-one",
                "https://github.com/example/repo.git",
                root,
                "main",
                RepositoryRegistry.config_digest(b"config-v1"),
            )
        ]
    )


def test_validate_binds_git_root_and_remote_without_public_paths(tmp_path: Path) -> None:
    current = registry(make_repo(tmp_path)).validate("repo-one")
    assert current.allowed is True
    assert current.reason_code == "repository_verified"
    assert current.public()["root"] == "not_returned"
    assert current.public()["remote"] == "not_returned"


def test_remote_swap_fails_closed(tmp_path: Path) -> None:
    root = make_repo(tmp_path)
    subprocess.run(
        ["git", "-C", str(root), "config", "remote.origin.url", "https://github.com/other/repo.git"],
        check=True,
    )
    result = registry(root).validate("repo-one")
    assert result.allowed is False
    assert result.reason_code == "repository_remote_mismatch"


def test_symlinked_root_and_parent_are_not_accepted(tmp_path: Path) -> None:
    root = make_repo(tmp_path)
    link = tmp_path / "repo-link"
    link.symlink_to(root, target_is_directory=True)
    binding = RepositoryBinding(
        "repo-one", "https://github.com/example/repo.git", link, "main", RepositoryRegistry.config_digest(b"x")
    )
    result = RepositoryRegistry([binding]).validate("repo-one")
    assert result.allowed is False
    assert result.reason_code == "repository_root_untrusted"


@pytest.mark.parametrize("value", ["../escape", "/absolute", "~/home", "src/../tests", "https://host/file"])
def test_path_escape_and_uri_values_are_rejected(tmp_path: Path, value: str) -> None:
    with pytest.raises(RepositoryError, match="repository_path_escape"):
        registry(make_repo(tmp_path)).resolve_path("repo-one", value)


def test_resolve_path_is_root_relative_and_follows_no_escape(tmp_path: Path) -> None:
    root = make_repo(tmp_path)
    repositories = registry(root)
    path = repositories.resolve_path("repo-one", "src/codex_master")
    assert path == root / "src/codex_master"
    assert repositories.scope_digest("repo-one", "write", ("src",)) != repositories.scope_digest(
        "repo-one", "read", ("src",)
    )
    assert repositories.scope_digest("repo-one", "write", ("src", "tests")) == repositories.scope_digest(
        "repo-one", "write", ("tests", "src")
    )


def test_duplicate_repository_ids_are_rejected(tmp_path: Path) -> None:
    root = make_repo(tmp_path)
    binding = RepositoryBinding(
        "repo-one", "https://github.com/example/repo.git", root, "main", RepositoryRegistry.config_digest(b"x")
    )
    with pytest.raises(RepositoryError, match="duplicate_repository_id"):
        RepositoryRegistry([binding, binding])
