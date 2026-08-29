from __future__ import annotations

import hashlib
import importlib
from pathlib import Path

import pytest


CANONICAL_HEADER = (
    b'<!-- codex-master-common-policy:{"generation":1,"schema_version":1} -->\n'
)


def load_policy_api():
    try:
        return importlib.import_module("codex_master.hive_policy")
    except ModuleNotFoundError:
        pytest.fail("codex_master.hive_policy contract API is missing")


def write_policy(tmp_path: Path, content: bytes) -> Path:
    path = tmp_path / "common.md"
    path.write_bytes(content)
    return path


def test_loads_canonical_policy_with_complete_file_digest() -> None:
    policy_api = load_policy_api()
    path = Path("src/codex_master/markdown/common.md")
    expected_bytes = path.read_bytes()

    contract = policy_api.load_common_policy(path)

    assert contract.schema_version == 1
    assert contract.generation == 2
    assert contract.common_bytes == expected_bytes
    assert contract.common_digest == hashlib.sha256(expected_bytes).hexdigest()


@pytest.mark.parametrize(
    "content",
    [
        b"# Common Hive context\n",
        b"# Preamble\n" + CANONICAL_HEADER + b"# Policy\n",
        CANONICAL_HEADER + CANONICAL_HEADER + b"# Policy\n",
        b'<!-- codex-master-common-policy:{"generation":1,"schema_version":2} -->\n',
        b'<!-- codex-master-common-policy:{"generation":0,"schema_version":1} -->\n',
        b'<!-- codex-master-common-policy:{"generation":-1,"schema_version":1} -->\n',
        b'<!-- codex-master-common-policy:{"generation":true,"schema_version":1} -->\n',
        b'<!-- codex-master-common-policy:{"extra":1,"generation":1,"schema_version":1} -->\n',
        b'<!-- codex-master-common-policy:{"schema_version":1,"generation":1} -->\n',
        b'<!-- codex-master-common-policy:{"generation": 1,"schema_version":1} -->\n',
        b'<!-- codex-master-common-policy:{"generation":1,"schema_version":1} -->\r\n',
        CANONICAL_HEADER + b"\xff\n",
    ],
    ids=[
        "missing",
        "not-first",
        "duplicated",
        "unknown-schema",
        "zero-generation",
        "negative-generation",
        "boolean-generation",
        "unknown-field",
        "noncanonical-key-order",
        "noncanonical-whitespace",
        "noncanonical-newline",
        "invalid-utf8",
    ],
)
def test_rejects_invalid_policy_contracts(tmp_path: Path, content: bytes) -> None:
    policy_api = load_policy_api()
    path = write_policy(tmp_path, content)

    with pytest.raises(policy_api.CommonPolicyError):
        policy_api.load_common_policy(path)


def test_rejects_oversized_policy_before_accepting_content(tmp_path: Path) -> None:
    policy_api = load_policy_api()
    content = CANONICAL_HEADER + b"x" * (64 * 1024)
    path = write_policy(tmp_path, content)

    with pytest.raises(policy_api.CommonPolicyError):
        policy_api.load_common_policy(path)


def test_missing_policy_file_fails_closed(tmp_path: Path) -> None:
    policy_api = load_policy_api()
    with pytest.raises(policy_api.CommonPolicyError):
        policy_api.load_common_policy(tmp_path / "missing.md")


def test_projects_same_common_bytes_into_distinct_complete_provider_artifacts(
) -> None:
    policy_api = load_policy_api()
    contract = policy_api.load_common_policy()

    projection = contract.project("worker")

    class_file = "AGENTS.class-worker.md"
    expected_codex = contract.common_bytes + (
        "\n\n## Active class profile\n\n"
        f"Read `./{class_file}` before acting. Only that class profile is active in this home.\n"
    ).encode("utf-8")
    expected_gemini = contract.common_bytes + (
        f"\n\n## Active class profile\n\n@./{class_file}\n"
    ).encode("utf-8")

    assert projection.class_file_name == class_file
    assert projection.codex.common_bytes == contract.common_bytes
    assert projection.gemini.common_bytes == contract.common_bytes
    assert projection.codex.common_digest == contract.common_digest
    assert projection.gemini.common_digest == contract.common_digest
    assert projection.codex.artifact_bytes == expected_codex
    assert projection.gemini.artifact_bytes == expected_gemini
    assert projection.codex.artifact_bytes != projection.gemini.artifact_bytes
    assert projection.codex.artifact_digest == hashlib.sha256(expected_codex).hexdigest()
    assert projection.gemini.artifact_digest == hashlib.sha256(expected_gemini).hexdigest()


@pytest.mark.parametrize("profile", ["", "../worker", "Worker", "worker.md", "a" * 65])
def test_rejects_invalid_class_profile_references(profile: str) -> None:
    policy_api = load_policy_api()
    contract = policy_api.load_common_policy()

    with pytest.raises(policy_api.CommonPolicyError):
        contract.project(profile)


def test_common_policy_contains_complete_no_transition_semantics() -> None:
    policy_api = load_policy_api()
    policy = " ".join(
        policy_api.load_common_policy().common_bytes.decode("utf-8").split()
    )

    required_meanings = [
        "keine fortlebende Übergangslösung",
        "Zielpfad neu bauen und testen",
        "Zustand parallel migrieren, wo sicher",
        "atomar umschalten",
        "Altpfad abschneiden und entfernen",
        "sichtbaren Ausfall akzeptieren",
        "kanonischem Profil, Policy, Credentials und ResumeCapsule",
        "Einmalige Migration ist erlaubt",
        "kein Reader, Writer, Router, Fallback oder Kompatibilitätspfad",
    ]

    for meaning in required_meanings:
        assert meaning in policy


def test_common_policy_requires_function_tests_and_minimal_test_execution() -> None:
    policy_api = load_policy_api()
    policy = " ".join(
        policy_api.load_common_policy().common_bytes.decode("utf-8").split()
    )

    required_meanings = [
        "Jede produktive Funktion braucht mindestens einen eindeutig zugeordneten, ausführbaren Test",
        "jede Funktion einen eigenen Fall besitzen",
        "so wenig Tests wie möglich, so viele wie nötig",
        "Zuerst den kleinstmöglichen gezielten Test für die Funktion ausführen",
        "Voll- und Release-Gates bleiben verbindlich",
    ]

    for meaning in required_meanings:
        assert meaning in policy
