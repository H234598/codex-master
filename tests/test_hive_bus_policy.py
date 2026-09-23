import ast
from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from the_hive.hive.authority import AuthorityContext, AuthorityEngine
from the_hive.hive.bus_policy import (
    QueenTopicDelegationV1,
    validate_active_queen_topic_delegations,
    validate_queen_topic_delegation_v1,
)
from the_hive.hive.bus_types import HiveBusContractError
from the_hive.hive.principals import Principal, PrincipalRegistry
from the_hive.hive.repositories import RepositoryBinding, RepositoryRegistry


NOW = datetime(2026, 9, 23, 12, tzinfo=timezone.utc)
DIGEST = "sha256:" + "a" * 64
GENERATION = "sha256:" + "b" * 64


def _principal(
    principal_id: str,
    class_id: str,
    parent_principal_id: str | None,
    repo_id: str | None,
    *,
    state: str = "active",
) -> Principal:
    return Principal(
        principal_id,
        class_id,
        parent_principal_id,
        "profile",
        "repository" if repo_id is not None else "global",
        repo_id,
        state,
        DIGEST,
        1,
    )


def _authority(tmp_path: Path) -> AuthorityEngine:
    root_one = tmp_path / "repo-one"
    root_two = tmp_path / "repo-two"
    root_one.mkdir()
    root_two.mkdir()
    principals = PrincipalRegistry()
    principals.create(_principal("godbee-main", "godbee", None, None))
    principals.create(_principal("queen-topic", "queen", "godbee-main", "repo-one"))
    principals.create(
        _principal("queen-integration", "koenigin", "godbee-main", "repo-one")
    )
    principals.create(_principal("queen-other", "queen", "godbee-main", "repo-two"))
    principals.create(_principal("lead-one", "teamlead", "queen-topic", "repo-one"))
    principals.create(
        _principal("queen-retired", "queen", "godbee-main", "repo-one", state="retired")
    )
    repositories = RepositoryRegistry(
        (
            RepositoryBinding(
                "repo-one", "https://example.invalid/repo-one", root_one, "main", DIGEST
            ),
            RepositoryBinding(
                "repo-two", "https://example.invalid/repo-two", root_two, "main", DIGEST
            ),
        )
    )
    return AuthorityEngine(AuthorityContext(principals, repositories, {}))


def _delegation(**changes: object) -> QueenTopicDelegationV1:
    values: dict[str, object] = {
        "schema_version": 1,
        "repo_id": "repo-one",
        "topic_id": "repo/repo-one/topic/topic-one",
        "plan_digest": DIGEST,
        "exclusive_paths": ("src/topic_one.py",),
        "topic_queen_principal_id": "queen-topic",
        "integration_queen_principal_id": "queen-integration",
        "authority_generation": GENERATION,
        "issued_at_utc": NOW,
        "expires_at_utc": NOW + timedelta(seconds=60),
    }
    values.update(changes)
    return QueenTopicDelegationV1(**values)  # type: ignore[arg-type]


def test_valid_delegation_is_immutable_deterministic_and_pure(tmp_path: Path) -> None:
    authority = _authority(tmp_path)
    first = _delegation()
    second = _delegation()

    assert first == second
    assert validate_queen_topic_delegation_v1(first, authority=authority) is first
    assert validate_active_queen_topic_delegations((first,), authority=authority) == (
        first,
    )
    with pytest.raises(FrozenInstanceError):
        first.repo_id = "repo-two"  # type: ignore[misc]


@pytest.mark.parametrize("ttl_seconds", (1, 86_400))
def test_ttl_inclusive_bounds_are_valid(tmp_path: Path, ttl_seconds: int) -> None:
    authority = _authority(tmp_path)
    delegation = _delegation(expires_at_utc=NOW + timedelta(seconds=ttl_seconds))

    assert (
        validate_queen_topic_delegation_v1(delegation, authority=authority)
        is delegation
    )


def test_maximum_exclusive_path_count_is_valid(tmp_path: Path) -> None:
    authority = _authority(tmp_path)
    paths = tuple(f"src/path-{index:03}.py" for index in range(256))
    delegation = _delegation(exclusive_paths=paths)

    assert (
        validate_queen_topic_delegation_v1(delegation, authority=authority)
        is delegation
    )


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("topic_queen_principal_id", "queen-retired"),
        ("topic_queen_principal_id", "queen-missing"),
        ("topic_queen_principal_id", "lead-one"),
        ("integration_queen_principal_id", "queen-topic"),
        ("integration_queen_principal_id", "queen-other"),
    ),
)
def test_principals_must_be_distinct_active_repo_queens(
    tmp_path: Path, field: str, value: str
) -> None:
    authority = _authority(tmp_path)

    with pytest.raises(HiveBusContractError, match="BUS_E_ACL_DENIED"):
        validate_queen_topic_delegation_v1(
            _delegation(**{field: value}), authority=authority
        )


@pytest.mark.parametrize("repo_id", ("repo-missing", "repo-two"))
def test_repository_must_exist_and_match_both_queens(
    tmp_path: Path, repo_id: str
) -> None:
    authority = _authority(tmp_path)

    expected = "BUS_E_REPO_SCOPE" if repo_id == "repo-missing" else "BUS_E_ACL_DENIED"
    changes: dict[str, object] = {"repo_id": repo_id}
    if repo_id == "repo-two":
        changes["topic_id"] = "repo/repo-two/topic/topic-one"
    with pytest.raises(HiveBusContractError, match=expected):
        validate_queen_topic_delegation_v1(_delegation(**changes), authority=authority)


def test_s0_repo_topic_namespace_must_match_delegation_repository() -> None:
    with pytest.raises(HiveBusContractError, match="BUS_E_REPO_SCOPE"):
        _delegation(topic_id="repo/repo-two/topic/topic-one")


@pytest.mark.parametrize(
    ("field", "value", "code"),
    (
        ("topic_id", "not/a/registered/topic/form", "BUS_E_TOPIC_INVALID"),
        ("exclusive_paths", (), "BUS_E_SCHEMA"),
        ("exclusive_paths", ("",), "BUS_E_REPO_SCOPE"),
        ("exclusive_paths", ("/absolute.py",), "BUS_E_REPO_SCOPE"),
        ("exclusive_paths", ("../outside.py",), "BUS_E_REPO_SCOPE"),
        ("exclusive_paths", ("src/one.py", "src/one.py"), "BUS_E_SCHEMA"),
    ),
)
def test_topic_and_exclusive_paths_are_fail_closed(
    tmp_path: Path, field: str, value: object, code: str
) -> None:
    authority = _authority(tmp_path)

    with pytest.raises(HiveBusContractError, match=code):
        validate_queen_topic_delegation_v1(
            _delegation(**{field: value}), authority=authority
        )


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("schema_version", 2),
        ("plan_digest", "sha256:" + "A" * 64),
        ("authority_generation", "generation-one"),
        ("authority_generation", "sha256:" + "B" * 64),
        ("issued_at_utc", datetime(2026, 9, 23, 12)),
        (
            "issued_at_utc",
            datetime(2026, 9, 23, 14, tzinfo=timezone(timedelta(hours=2))),
        ),
        ("expires_at_utc", datetime(2026, 9, 23, 12)),
        (
            "expires_at_utc",
            datetime(2026, 9, 23, 14, tzinfo=timezone(timedelta(hours=2))),
        ),
        ("expires_at_utc", NOW),
        ("expires_at_utc", NOW + timedelta(seconds=86_401)),
    ),
)
def test_schema_digest_generation_and_utc_ttl_are_exact(
    field: str, value: object
) -> None:
    with pytest.raises(HiveBusContractError, match="BUS_E_SCHEMA"):
        _delegation(**{field: value})


def test_more_than_maximum_exclusive_paths_are_rejected() -> None:
    paths = tuple(f"src/path-{index:03}.py" for index in range(257))

    with pytest.raises(HiveBusContractError, match="BUS_E_SCHEMA"):
        _delegation(exclusive_paths=paths)


def test_active_set_rejects_topic_and_resolved_path_collisions(tmp_path: Path) -> None:
    authority = _authority(tmp_path)
    current = _delegation()
    same_topic_new_generation = _delegation(authority_generation="sha256:" + "c" * 64)
    overlapping_path = _delegation(
        topic_id="repo/repo-one/topic/topic-two",
        exclusive_paths=("src",),
    )

    with pytest.raises(HiveBusContractError, match="BUS_E_ACL_DENIED"):
        validate_active_queen_topic_delegations(
            (current, same_topic_new_generation), authority=authority
        )
    with pytest.raises(HiveBusContractError, match="BUS_E_ACL_DENIED"):
        validate_active_queen_topic_delegations(
            (current, overlapping_path), authority=authority
        )


def test_single_delegation_rejects_overlapping_resolved_paths(tmp_path: Path) -> None:
    authority = _authority(tmp_path)
    delegation = _delegation(exclusive_paths=("src", "src/file.py"))

    with pytest.raises(HiveBusContractError, match="BUS_E_ACL_DENIED"):
        validate_queen_topic_delegation_v1(delegation, authority=authority)


def test_active_set_rejects_same_repo_topic_generation_tuple(tmp_path: Path) -> None:
    authority = _authority(tmp_path)
    current = _delegation()
    duplicate = _delegation(exclusive_paths=("tests/topic_one.py",))

    with pytest.raises(HiveBusContractError, match="BUS_E_ACL_DENIED"):
        validate_active_queen_topic_delegations(
            (current, duplicate), authority=authority
        )


def test_policy_ast_has_no_forbidden_runtime_or_storage_dependencies() -> None:
    source_path = Path(__file__).parents[1] / "src/the_hive/hive/bus_policy.py"
    source = source_path.read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported_modules = {
        node.module
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module is not None
    } | {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    assert imported_modules == {
        "__future__",
        "dataclasses",
        "datetime",
        "the_hive.hive.authority",
        "the_hive.hive.bus_types",
        "the_hive.hive.capabilities",
        "the_hive.hive.principals",
        "the_hive.hive.repositories",
        "the_hive.hive.types",
    }
    names = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)} | {
        node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)
    }
    called = {
        node.func.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    } | {
        node.func.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    }
    excluded_slice_names = {
        "Archive",
        "BusSubscriptionSetV1",
        "CapabilityToken",
        "Cursor",
        "DiagnosticV2",
        "HiveBusStore",
        "Migration",
        "Outbox",
        "Persistence",
        "Revocation",
        "Runtime",
        "Service",
        "Store",
        "Subscription",
        "Transport",
        "Token",
    }
    excluded_calls = {
        "ack",
        "connect",
        "create_subscription",
        "execute",
        "fetch",
        "issue_token",
        "load",
        "mkdir",
        "open",
        "persist",
        "poll",
        "publish",
        "record_manifest_bytes",
        "revoke_token",
        "revoke",
        "send",
        "subscribe",
        "unlink",
        "write_bytes",
        "write_text",
    }

    assert not names & excluded_slice_names
    assert not called & excluded_calls
    assert "HIVE_BUS_SCHEMA_VERSION" not in source
    assert "QUEEN_CLASSES" in source
