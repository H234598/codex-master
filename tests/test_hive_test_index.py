from __future__ import annotations

import json

import pytest

from codex_master.hive.test_index import TestIndexError as IndexError
from codex_master.hive.test_index import TestIndexV1 as IndexV1


DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64
DIGEST_C = "sha256:" + "c" * 64


def valid_index() -> dict[str, object]:
    function_id = "python:src/example.py:Example.run"
    test_id = "pytest:tests/test_example.py:test_example_run"
    return {
        "schema_version": 1,
        "generation": 1,
        "repository_id": "codex-master",
        "indexer_version": "hive-test-index-v1",
        "source_root_digest": DIGEST_A,
        "test_root_digest": DIGEST_B,
        "dependency_policy_digest": DIGEST_C,
        "functions": [
            {
                "function_id": function_id,
                "language": "python",
                "path": "src/example.py",
                "qualified_name": "Example.run",
                "source_digest": DIGEST_A,
                "dependency_digest": DIGEST_B,
                "test_ids": [test_id],
                "cooldown_class": "deterministic",
                "risk": "read_only",
                "generated": False,
            }
        ],
        "tests": [
            {
                "test_id": test_id,
                "runner": "pytest",
                "path": "tests/test_example.py",
                "node_id": "test_example_run",
                "test_digest": DIGEST_A,
                "assertion_digest": DIGEST_B,
                "covers": [function_id],
                "kind": "unit",
                "timeout_seconds": 30,
                "hermeticity": "hermetic",
                "required_resources": [],
                "cooldown_class": "deterministic",
            }
        ],
        "gates": [],
    }


def test_index_round_trips_as_canonical_json() -> None:
    index = IndexV1.from_mapping(valid_index())

    assert index.canonical_bytes().endswith(b"\n")
    assert json.loads(index.canonical_bytes()) == valid_index()
    assert index.digest.startswith("sha256:")


@pytest.mark.parametrize(
    ("mutate", "reason"),
    [
        (lambda value: value.update(schema_version=True), "test.index_invalid"),
        (lambda value: value.update(extra=True), "test.index_invalid"),
        (lambda value: value["functions"][0].update(path="../escape.py"), "test.index_invalid"),
        (lambda value: value["functions"][0].update(test_ids=[]), "test.function_unindexed"),
        (lambda value: value["tests"][0].update(assertion_digest="sha256:" + "x" * 64), "test.assertion_missing"),
        (lambda value: value["tests"][0].update(covers=["python:src/missing.py:run"]), "test.index_invalid"),
    ],
)
def test_index_rejects_noncanonical_or_unbound_records(mutate, reason: str) -> None:
    value = valid_index()
    mutate(value)

    with pytest.raises(IndexError, match=reason):
        IndexV1.from_mapping(value)


def test_index_requires_sorted_unique_identity_lists() -> None:
    value = valid_index()
    value["functions"] = [value["functions"][0], dict(value["functions"][0])]

    with pytest.raises(IndexError, match="test.index_invalid"):
        IndexV1.from_mapping(value)
