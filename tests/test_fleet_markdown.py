from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from codex_master import fleet_markdown, server as server_module
from codex_master.fleet_registry import AgentDescriptor, Provider, RunnerKind
from codex_master.hive_policy import (
    MAX_COMMON_POLICY_BYTES,
    CommonPolicyError,
    load_common_policy,
)


_MARKDOWN_ROOT = Path(fleet_markdown.__file__).with_name("markdown")
_COMMON_BYTES = (_MARKDOWN_ROOT / "common.md").read_bytes()
_VISUAL_COMPANION_RULE = """## Visual Companion

Entscheide pro Frage oder Arbeitsschritt, nicht pauschal pro Session. Bei
visuellen Inhalten oder visuellen Entscheidungen (etwa App-/Mobile-/UI-Design,
GitHub-Docs-Webseiten, Layout, visueller Hierarchie oder visuellen
Designvergleichen) lade zuerst `superpowers:brainstorming` und danach dessen
`visual-companion.md` vollständig, bevor du eine visuelle Richtung festlegst
oder visuelle Arbeit delegierst. Textuelle Anforderungen, API-, Datenmodell-
oder Backendentscheidungen sowie reine Trade-off-Listen lösen diese Regel
nicht aus. Fehlt die Companion-Ressource, behaupte nicht, sie sei geladen:
blockiere oder eskaliere menschenlesbar mit
`visual_companion_unavailable`. Wenn providerseitig die für den Companion
erforderlichen ausführbaren Scripts nicht verfügbar sind, darf der Guide
geladen werden, aber die Ausführung bleibt explizit
`visual_companion_unavailable`; verwende keine Scheinfunktion oder
Übergangslösung.
""".encode("utf-8")
_PCLOUD_RIPGREP_GLOBS = (
    b"--glob '!pCloudDrive/**'",
    b"--glob '!pCloud/**'",
    b"--glob '!**/pCloudDrive/**'",
    b"--glob '!**/pCloud/**'",
)
_PCLOUD_ROOT_RULE = (
    "`/home/teladi/pCloud` darf nicht als Suchwurzel übergeben werden"
).encode("utf-8")
_PCLOUD_GREP_RULE = "Normales GNU `grep` nicht verwenden".encode("utf-8")
_PCLOUD_EXCEPTION_RULE = (
    "Explizite Suche im jeweils benannten pCloud-Namensraum ist die einzige "
    "Ausnahme"
).encode("utf-8")


def _agent(
    runner: RunnerKind = RunnerKind.CODEX_CLI,
    skill_profile: str = "worker",
) -> AgentDescriptor:
    provider = (
        Provider.GEMINI_API
        if runner is RunnerKind.GEMINI_CLI
        else Provider.OPENAI_CHATGPT
    )
    return AgentDescriptor(
        agent_id="a1",
        series_prefix="a",
        ordinal=1,
        label="Agentin A1",
        runner=runner,
        provider=provider,
        model="test-model",
        account_id=None,
        home=Path("/unused/a1"),
        session="agent-a1",
        enabled=True,
        skill_profile=skill_profile,
    )


def test_codex_projection_preserves_artifact_api_and_profile_path() -> None:
    agent = _agent()
    class_name = "AGENTS.class-worker.md"
    expected_primary = (
        _COMMON_BYTES
        + (
            "\n\n## Active class profile\n\n"
            f"Read `./{class_name}` before acting. "
            "Only that class profile is active in this home.\n"
        ).encode()
    )
    expected_artifacts = {
        "AGENTS.md": expected_primary,
        class_name: (_MARKDOWN_ROOT / "classes" / "worker.md").read_bytes(),
    }

    projection = fleet_markdown.fleet_markdown_projection(agent)

    assert dict(projection.artifacts) == expected_artifacts
    assert fleet_markdown.fleet_markdown_artifacts(agent) == expected_artifacts
    assert type(fleet_markdown.fleet_markdown_artifacts(agent)) is dict
    assert fleet_markdown.fleet_markdown_file_names(agent) == set(expected_artifacts)


def test_gemini_projection_preserves_provider_paths() -> None:
    agent = _agent(RunnerKind.GEMINI_CLI)
    class_name = "AGENTS.class-worker.md"
    expected_primary = (
        _COMMON_BYTES + (f"\n\n## Active class profile\n\n@./{class_name}\n").encode()
    )
    expected_artifacts = {
        ".gemini/GEMINI.md": expected_primary,
        f".gemini/{class_name}": (
            _MARKDOWN_ROOT / "classes" / "worker.md"
        ).read_bytes(),
    }

    projection = fleet_markdown.fleet_markdown_projection(agent)

    assert dict(projection.artifacts) == expected_artifacts
    assert fleet_markdown.fleet_markdown_artifacts(agent) == expected_artifacts


def test_providers_share_exact_common_prefix_and_only_reference_class_body() -> None:
    class_name = b"AGENTS.class-worker.md"
    worker_body = (_MARKDOWN_ROOT / "classes" / "worker.md").read_bytes()
    codex = fleet_markdown.fleet_markdown_projection(_agent())
    gemini = fleet_markdown.fleet_markdown_projection(_agent(RunnerKind.GEMINI_CLI))

    for projection in (codex, gemini):
        primary = projection.artifacts[projection.metadata.provider_artifact_name]
        suffix = primary[len(_COMMON_BYTES) :]
        assert primary[: len(_COMMON_BYTES)] == _COMMON_BYTES
        assert suffix.count(class_name) == 1
        assert worker_body not in primary


def test_pcloud_search_policy_projects_to_all_effective_catalog_profiles_and_provider_homes() -> None:
    contract = load_common_policy()
    profiles = server_module._known_runtime_skill_profiles("test_invalid_profile")
    assert profiles == frozenset(
        {
            "goettin",
            "gottbiene",
            "koenigin",
            "spezialistin",
            "teamleiterin",
            "worker",
        }
    )

    for runner in (RunnerKind.CODEX_CLI, RunnerKind.GEMINI_CLI):
        for profile in sorted(profiles):
            projection = fleet_markdown.fleet_markdown_projection(
                _agent(runner, profile)
            )
            primary = projection.artifacts[projection.metadata.provider_artifact_name]
            class_artifact = projection.artifacts[
                projection.metadata.class_artifact_name
            ]
            normalized_primary = b" ".join(primary.split())
            class_name = f"AGENTS.class-{profile}.md"
            expected_class_artifact_name = (
                f".gemini/{class_name}"
                if runner is RunnerKind.GEMINI_CLI
                else class_name
            )

            assert primary.startswith(contract.common_bytes)
            assert projection.metadata.class_profile == profile
            assert projection.metadata.class_artifact_name == expected_class_artifact_name
            for glob in _PCLOUD_RIPGREP_GLOBS:
                assert primary.count(glob) == 1
            assert _PCLOUD_GREP_RULE in normalized_primary
            assert _PCLOUD_ROOT_RULE in normalized_primary
            assert _PCLOUD_EXCEPTION_RULE in normalized_primary
            assert not class_artifact.startswith(contract.common_bytes)
            for glob in _PCLOUD_RIPGREP_GLOBS:
                assert glob not in class_artifact
            assert _PCLOUD_GREP_RULE not in class_artifact
            assert _PCLOUD_ROOT_RULE not in class_artifact
            assert _PCLOUD_EXCEPTION_RULE not in class_artifact


def test_visual_companion_rule_is_identical_in_teamlead_profiles_and_providers() -> (
    None
):
    teamlead_bodies = {
        profile: (_MARKDOWN_ROOT / "classes" / f"{profile}.md").read_bytes()
        for profile in ("teamleiterin", "teamlead")
    }

    for body in teamlead_bodies.values():
        assert body.count(_VISUAL_COMPANION_RULE) == 1

    for runner in (RunnerKind.CODEX_CLI, RunnerKind.GEMINI_CLI):
        for profile, body in teamlead_bodies.items():
            projection = fleet_markdown.fleet_markdown_projection(
                _agent(runner, profile)
            )
            assert projection.artifacts[projection.metadata.class_artifact_name] == body
            assert (
                _VISUAL_COMPANION_RULE
                in projection.artifacts[projection.metadata.class_artifact_name]
            )


def test_visual_companion_rule_is_absent_from_worker_and_queen_profiles() -> None:
    for profile in ("worker", "koenigin"):
        body = (_MARKDOWN_ROOT / "classes" / f"{profile}.md").read_bytes()
        assert _VISUAL_COMPANION_RULE not in body

        for runner in (RunnerKind.CODEX_CLI, RunnerKind.GEMINI_CLI):
            projection = fleet_markdown.fleet_markdown_projection(
                _agent(runner, profile)
            )
            assert (
                _VISUAL_COMPANION_RULE
                not in projection.artifacts[projection.metadata.class_artifact_name]
            )


def test_projection_metadata_exposes_bounded_contract_and_full_digest() -> None:
    projection = fleet_markdown.fleet_markdown_projection(_agent())
    metadata = projection.metadata
    primary = projection.artifacts[metadata.provider_artifact_name]

    assert metadata.schema_version == 1
    assert metadata.generation == 8
    assert metadata.common_digest == hashlib.sha256(_COMMON_BYTES).hexdigest()
    assert metadata.common_size == len(_COMMON_BYTES) <= MAX_COMMON_POLICY_BYTES
    assert metadata.provider_artifact_name == "AGENTS.md"
    assert metadata.provider_artifact_digest == hashlib.sha256(primary).hexdigest()
    assert metadata.provider_artifact_size == len(primary)
    assert metadata.class_profile == "worker"
    assert metadata.class_artifact_name == "AGENTS.class-worker.md"


def test_provider_projection_digests_are_deterministic_and_distinct() -> None:
    codex_first = fleet_markdown.fleet_markdown_projection(_agent())
    codex_second = fleet_markdown.fleet_markdown_projection(_agent())
    gemini = fleet_markdown.fleet_markdown_projection(_agent(RunnerKind.GEMINI_CLI))

    assert codex_first.metadata == codex_second.metadata
    assert dict(codex_first.artifacts) == dict(codex_second.artifacts)
    assert codex_first.metadata.common_digest == gemini.metadata.common_digest
    assert (
        codex_first.metadata.provider_artifact_digest
        != gemini.metadata.provider_artifact_digest
    )


def test_canonical_header_remains_first_in_both_provider_artifacts() -> None:
    expected_header = (
        b'<!-- codex-master-common-policy:{"generation":8,"schema_version":1} -->'
    )

    for runner in (RunnerKind.CODEX_CLI, RunnerKind.GEMINI_CLI):
        projection = fleet_markdown.fleet_markdown_projection(_agent(runner))
        primary = projection.artifacts[projection.metadata.provider_artifact_name]
        assert primary.splitlines()[0] == expected_header


def test_both_provider_projections_carry_same_annotation_response_policy() -> None:
    contract = load_common_policy()
    required_inline_link = "[(A)](<Antwortziel>#<Antwortueberschrift>)".encode("utf-8")
    obsolete_line = (
        "Beantwortung der Frage am TT.MMJJJJ durch: <Biene> -: "
        "[[<Antwortziel>#<Antwortüberschrift>|<Antwortüberschrift>]]"
    ).encode("utf-8")

    projections = [
        fleet_markdown.fleet_markdown_projection(_agent()),
        fleet_markdown.fleet_markdown_projection(_agent(RunnerKind.GEMINI_CLI)),
    ]

    for projection in projections:
        primary = projection.artifacts[projection.metadata.provider_artifact_name]
        assert primary.startswith(contract.common_bytes)
        assert required_inline_link in primary
        assert obsolete_line not in primary
        assert projection.metadata.common_digest == contract.common_digest
        assert projection.metadata.generation == contract.generation == 8


def test_both_provider_projections_carry_corrected_annotation_heading_and_guards() -> (
    None
):
    contract = load_common_policy()
    required_fragments = [
        (
            "## <exakte Annotation-Überschrift ohne finale ID> — "
            "[<Annotation-ID>](<eindeutiger Link auf referenzierten "
            "Annotationsabschnitt oder dessen Überschrift>)"
        ).encode("utf-8"),
        "sichtbare ID bleibt unverändert".encode("utf-8"),
        "kein Wikilink für den Heading-Identifier".encode("utf-8"),
        b"fail-closed",
        "passender vorhandener Rückverweis wird wiederverwendet".encode("utf-8"),
        "nichtpassender vorhandener Rückverweis ist ein Blocker".encode("utf-8"),
        "nie eine zweite Zeile".encode("utf-8"),
    ]

    projections = [
        fleet_markdown.fleet_markdown_projection(_agent()),
        fleet_markdown.fleet_markdown_projection(_agent(RunnerKind.GEMINI_CLI)),
    ]

    for projection in projections:
        primary = projection.artifacts[projection.metadata.provider_artifact_name]
        assert primary.startswith(contract.common_bytes)
        for fragment in required_fragments:
            assert fragment in primary
        assert projection.metadata.common_digest == contract.common_digest


def test_both_provider_projections_carry_identical_inline_and_multi_source_guards() -> (
    None
):
    contract = load_common_policy()
    required_fragments = [
        (
            "Eine Inline-Annotation verwendet die umgebende Markdown-Überschrift "
            "nur dann unverändert als Basisteil der Antwortüberschrift"
        ).encode("utf-8"),
        (
            "weder einen terminalen Annotation-Identifier noch einen "
            "konfliktierenden ID-Link enthält"
        ).encode("utf-8"),
        "Andernfalls gilt fail-closed: keine Dokumentmutation".encode("utf-8"),
        "niemals automatisch abschneiden, entfernen oder normalisieren".encode("utf-8"),
        (
            "Die Antwortüberschrift hängt ausschließlich den aktuellen verlinkten "
            "Annotation-Identifier am Ende an"
        ).encode("utf-8"),
        (
            "Bei mehreren Quellkapiteln sind vor jeder Mutation alle tatsächlich "
            "referenzierten Quellüberschriften eindeutig aufzulösen"
        ).encode("utf-8"),
        (
            "Der Antworttext enthält für jede tatsächlich referenzierte "
            "Quellüberschrift genau einen normalen Markdown-Link"
        ).encode("utf-8"),
        (
            "Jeder jeweilige Quellabschnitt enthält genau einen idempotenten "
            "Rückverweis auf dieselbe Antwort"
        ).encode("utf-8"),
        (
            "Fehlt, ist mehrdeutig oder konfliktierend eine Quelle, wird die "
            "gesamte Mehrquellenmutation fail-closed blockiert"
        ).encode("utf-8"),
        "weder Antwortkapitel noch irgendein Rückverweis".encode("utf-8"),
    ]

    for runner in (RunnerKind.CODEX_CLI, RunnerKind.GEMINI_CLI):
        projection = fleet_markdown.fleet_markdown_projection(_agent(runner))
        primary = projection.artifacts[projection.metadata.provider_artifact_name]
        normalized_primary = b" ".join(primary.split())

        assert primary[: len(contract.common_bytes)] == contract.common_bytes
        for fragment in required_fragments:
            assert fragment in normalized_primary
        assert projection.metadata.common_digest == contract.common_digest


def test_both_provider_projections_carry_same_generation_eight_policy_bytes() -> None:
    contract = load_common_policy()

    for runner in (RunnerKind.CODEX_CLI, RunnerKind.GEMINI_CLI):
        projection = fleet_markdown.fleet_markdown_projection(_agent(runner))
        primary = projection.artifacts[projection.metadata.provider_artifact_name]
        assert primary[: len(contract.common_bytes)] == contract.common_bytes
        assert projection.metadata.generation == contract.generation == 8


def test_both_provider_projections_carry_openai_stickiness_and_reset_gate() -> None:
    contract = load_common_policy()
    required_fragments = [
        "Bei aktiver OpenAI-Arbeit so lange wie möglich und mindestens themenbezogen auf demselben OpenAI-Account bleiben".encode(
            "utf-8"
        ),
        "Prompt-/Context-Cache accountgebunden ist".encode("utf-8"),
        "kein opportunistischer Wechsel".encode("utf-8"),
        "frischer, reset-konsistenter Snapshot über alle Accounts zugleich".encode(
            "utf-8"
        ),
        "unter 10% Rest im jeweils zeitlich höchsten vorhandenen Abo-Fenster; Monat vor Woche".encode(
            "utf-8"
        ),
        "Fehlende, stale, widersprüchliche oder nicht vergleichbare Daten blockieren automatische Aktion fail-closed".encode(
            "utf-8"
        ),
        "Account ohne Wochen-/Monatsfenster liefert keinen positiven Ersatz-Headroom".encode(
            "utf-8"
        ),
        "Session erhalten/schlafen/resumen, nicht opportunistisch rotieren".encode(
            "utf-8"
        ),
    ]

    for runner in (RunnerKind.CODEX_CLI, RunnerKind.GEMINI_CLI):
        projection = fleet_markdown.fleet_markdown_projection(_agent(runner))
        primary = projection.artifacts[projection.metadata.provider_artifact_name]

        assert primary.startswith(contract.common_bytes)
        for fragment in required_fragments:
            assert fragment in primary
        assert projection.metadata.generation == contract.generation == 8


def test_both_provider_projections_carry_side_effect_free_external_plan_handoff():
    contract = load_common_policy()
    required_fragments = [
        "Zwischenablage weder automatisch lesen, entdecken, verwenden noch verändern".encode(
            "utf-8"
        ),
        "bereits vorhandener Zwischenablageinhalt bleibt unverändert".encode("utf-8"),
        "validierten absoluten Markdown-Dateipfad exakt auf stdout".encode("utf-8"),
        "variierende sichtbare Desktop-Benachrichtigung".encode("utf-8"),
        "vollständigen absoluten Pfad enthalten".encode("utf-8"),
        "keine Aussage über Kopieren oder das Ablegen in die Zwischenablage".encode(
            "utf-8"
        ),
    ]

    for runner in (RunnerKind.CODEX_CLI, RunnerKind.GEMINI_CLI):
        projection = fleet_markdown.fleet_markdown_projection(_agent(runner))
        primary = projection.artifacts[projection.metadata.provider_artifact_name]
        normalized_primary = b" ".join(primary.split())

        assert primary.startswith(contract.common_bytes)
        for fragment in required_fragments:
            assert fragment in normalized_primary
        for backend in (b"wl-copy", b"xclip", b"xsel"):
            assert backend not in primary
        assert projection.metadata.generation == contract.generation == 8


def test_both_provider_projections_carry_unencoded_local_file_link_contract() -> None:
    contract = load_common_policy()
    required_fragments = [
        b"[[Projekte/PVE4/Datei mit Leerzeichen|Text]]",
        b"[Text](<Projekte/PVE4/Datei mit Leerzeichen.md#Abschnitt>)",
        b"[Text](</absoluter/Pfad/Datei mit Leerzeichen.md:42>)",
        b"Never replace spaces in local filesystem link targets with `%20`",
        b"Never use `file://` or `vscode://`",
    ]

    for runner in (RunnerKind.CODEX_CLI, RunnerKind.GEMINI_CLI):
        projection = fleet_markdown.fleet_markdown_projection(_agent(runner))
        primary = projection.artifacts[projection.metadata.provider_artifact_name]
        normalized_primary = b" ".join(primary.split())

        assert primary.startswith(contract.common_bytes)
        for fragment in required_fragments:
            assert fragment in normalized_primary
        assert projection.metadata.common_digest == contract.common_digest


@pytest.mark.parametrize("profile", ["../../worker", "worker.md", "", "x" * 65])
def test_invalid_profile_falls_back_only_to_generic_class_projection(
    profile: str,
) -> None:
    projection = fleet_markdown.fleet_markdown_projection(_agent(skill_profile=profile))

    assert projection.metadata.class_profile == "generic"
    assert projection.metadata.class_artifact_name == "AGENTS.class-generic.md"
    assert (
        projection.artifacts["AGENTS.class-generic.md"]
        == (_MARKDOWN_ROOT / "classes" / "generic.md").read_bytes()
    )
    assert (
        projection.metadata.common_digest == hashlib.sha256(_COMMON_BYTES).hexdigest()
    )


def test_profile_normalization_and_known_class_body_are_preserved() -> None:
    projection = fleet_markdown.fleet_markdown_projection(
        _agent(skill_profile="  WORKER  ")
    )

    assert projection.metadata.class_profile == "worker"
    assert (
        projection.artifacts["AGENTS.class-worker.md"]
        == (_MARKDOWN_ROOT / "classes" / "worker.md").read_bytes()
    )


def test_unknown_valid_profile_keeps_path_and_uses_existing_placeholder() -> None:
    projection = fleet_markdown.fleet_markdown_projection(
        _agent(skill_profile="specialist")
    )

    assert projection.metadata.class_profile == "specialist"
    assert projection.metadata.class_artifact_name == "AGENTS.class-specialist.md"
    assert projection.artifacts["AGENTS.class-specialist.md"] == (
        b"# Hive class profile: `specialist`\n\n"
        b"This profile has no additional class-specific policy yet. Follow the "
        b"common Hive context and the assigned task scope.\n"
    )


def test_malformed_common_header_error_propagates_without_policy_fallback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    malformed_policy = tmp_path / "common.md"
    malformed_policy.write_bytes(b"# missing contract header\n")
    monkeypatch.setattr(
        fleet_markdown,
        "load_common_policy",
        lambda: load_common_policy(malformed_policy),
    )

    with pytest.raises(CommonPolicyError, match="common_policy_header_invalid"):
        fleet_markdown.fleet_markdown_artifacts(_agent())
