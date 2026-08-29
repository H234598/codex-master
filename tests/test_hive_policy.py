from __future__ import annotations

import hashlib
import importlib
from pathlib import Path

import pytest


CANONICAL_HEADER = (
    b'<!-- codex-master-common-policy:{"generation":4,"schema_version":1} -->\n'
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
    assert contract.generation == 4
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


def test_common_policy_contains_bidirectional_annotation_response_contract() -> None:
    policy_api = load_policy_api()
    raw_policy = policy_api.load_common_policy().common_bytes.decode("utf-8")
    policy = " ".join(raw_policy.split())

    required_meanings = [
        "eigenes Kapitel am Dokumentende",
        "exakte Annotation-Überschrift",
        "Markdown-Selbstlink",
        "sichtbare ID bleibt unverändert",
        "genau eine idempotente",
        "konkrete Biene",
        "konkrete Antwortüberschrift",
        "Retry",
        "data-annotation-note",
        "data-annotation-id",
        "Antworten, Erklärungen, ADRs und Fragen",
    ]

    for meaning in required_meanings:
        assert meaning in policy
    assert (
        "Beantwortung der Frage am TT.MMJJJJ durch: <Biene> -: "
        "[[<Antwortziel>#<Antwortüberschrift>|<Antwortüberschrift>]]"
        in raw_policy
    )


def test_common_policy_requires_markdown_annotation_response_heading() -> None:
    policy_api = load_policy_api()
    raw_policy = policy_api.load_common_policy().common_bytes.decode("utf-8")
    heading_template = (
        "## <exakte Annotation-Überschrift ohne finale ID> — "
        "[<Annotation-ID>](<eindeutiger Link auf referenzierten "
        "Annotationsabschnitt oder dessen Überschrift>)"
    )

    assert heading_template in raw_policy
    for meaning in (
        "sichtbare ID bleibt unverändert",
        "kein Wikilink für den Heading-Identifier",
        "Ziel zuerst eindeutig auflösen",
    ):
        assert meaning in " ".join(raw_policy.split())
    assert "[[#<Annotation-ID>|<Annotation-ID>]]" not in raw_policy


def test_common_policy_fails_closed_on_unresolved_or_conflicting_annotation_data() -> None:
    policy_api = load_policy_api()
    policy = " ".join(
        policy_api.load_common_policy().common_bytes.decode("utf-8").split()
    )

    required_meanings = [
        "Vor jeder Dokumentmutation",
        "Quellabschnitt",
        "Source-Heading-Markdownziel",
        "Annotation-ID",
        "Antwortziel",
        "Antwortüberschrift",
        "fehlend, mehrdeutig oder konfliktierend",
        "fail-closed",
        "weder die Quellzeile noch das Antwortkapitel",
        "passender vorhandener Rückverweis wird wiederverwendet",
        "nichtpassender vorhandener Rückverweis ist ein Blocker",
        "nie eine zweite Zeile",
    ]

    for meaning in required_meanings:
        assert meaning in policy


def test_common_policy_links_section_answers_without_requiring_annotation_id() -> None:
    policy_api = load_policy_api()
    policy = " ".join(
        policy_api.load_common_policy().common_bytes.decode("utf-8").split()
    )

    required_meanings = [
        (
            "Jede direkte Antwort auf einen Dokumentabschnitt ist auch ohne "
            "Annotation Marker bidirektional zu verlinken"
        ),
        (
            "Die Antwort enthält genau einen eindeutig aufgelösten Markdown-Link "
            "auf den Quellabschnitt oder seine Überschrift"
        ),
        (
            "Der Quellabschnitt enthält genau einen Rückverweis auf das konkrete "
            "Antwortziel und die konkrete Antwortüberschrift"
        ),
        (
            "Eine vorhandene Annotation-ID ist bei einer reinen "
            "Abschnittsantwort ein optionaler zusätzlicher Anker"
        ),
        "sie ist dafür nicht erforderlich",
        (
            "Bei einer direkten Antwort auf eine Annotation bleibt die "
            "Annotation-ID dagegen erforderlich"
        ),
    ]

    for meaning in required_meanings:
        assert meaning in policy


def test_common_policy_fails_closed_and_reuses_links_for_section_answers() -> None:
    policy_api = load_policy_api()
    policy = " ".join(
        policy_api.load_common_policy().common_bytes.decode("utf-8").split()
    )

    required_meanings = [
        "Vor jeder Dokumentmutation einer Abschnittsantwort",
        "Quelldokument",
        "Quellabschnitt",
        "Quellüberschrift",
        "Source-Link-Ziel",
        "Antwortziel",
        "Antwortüberschrift",
        "fehlende, mehrdeutige oder widersprüchliche Auflösung",
        "fail-closed",
        "weder Antwortkapitel noch Rückverweis",
        (
            "Passender vorhandener Rückverweis und passender vorhandener "
            "Antwortlink werden wiederverwendet"
        ),
        (
            "Ein konfliktierender vorhandener Rückverweis oder Antwortlink ist "
            "ein Blocker"
        ),
        "nie einen zweiten Rückverweis oder Antwortlink schreiben",
    ]

    for meaning in required_meanings:
        assert meaning in policy
