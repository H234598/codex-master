from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft202012Validator

from test_hive_test_evidence import receipt
from test_hive_test_index import DIGEST_A, valid_index


ROOT = Path(__file__).resolve().parents[1]


def schema(name: str) -> dict[str, object]:
    return json.loads((ROOT / "schemas" / name).read_text(encoding="utf-8"))


def test_test_index_schema_accepts_contract_and_rejects_unknown_fields() -> None:
    validator = Draft202012Validator(schema("hive-test-index-v1.schema.json"))
    value = valid_index()

    assert not list(validator.iter_errors(value))
    value["functions"][0]["surprise"] = True
    assert list(validator.iter_errors(value))


def test_evidence_receipt_schema_accepts_receipt_and_rejects_bool_integer() -> None:
    validator = Draft202012Validator(schema("hive-test-evidence-receipt-v1.schema.json"))
    value = receipt().public()

    assert not list(validator.iter_errors(value))
    value["duration_ms"] = True
    assert list(validator.iter_errors(value))


def test_status_schema_is_bounded_and_contains_no_raw_output() -> None:
    validator = Draft202012Validator(schema("hive-test-status-v1.schema.json"))
    value = {
        "schema_version": 1,
        "repository_id": "codex-master",
        "index_generation": 1,
        "index_digest": DIGEST_A,
        "counts": {
            "unverified": 0,
            "running": 0,
            "passed": 1,
            "failed": 0,
            "stale": 0,
            "blocked": 0,
        },
        "items": [
            {
                "test_id": "pytest:tests/test_example.py:test_example_run",
                "status": "passed",
                "last_duration_ms": 10,
                "cooldown_class": "deterministic",
                "reuse_eligible": True,
                "remaining_cooldown_seconds": 42,
                "reason_code": "test.evidence_reused",
            }
        ],
    }

    assert not list(validator.iter_errors(value))
    value["items"][0]["stdout"] = "secret"
    assert list(validator.iter_errors(value))
