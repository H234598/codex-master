"""Contract gate for the canonical the-hive-fleet skill router."""

from __future__ import annotations

import os
import re
from pathlib import Path


DEFAULT_ROOT = Path(__file__).resolve().parents[1] / "skills" / "the-hive-fleet"
RUNTIME_MIGRATION_POLICY = Path(
    "src/the_hive/markdown/runtime-migration-policy-v1.json"
)
RUNTIME_MIGRATION_POLICY_LINK = (
    "[Runtime-Migrationspolicy v1]"
    "(../../../src/the_hive/markdown/runtime-migration-policy-v1.json)"
)
ROADMAP = Path("ROADMAP.md")
EXPECTED_REFERENCES = {
    "references/common-invariants.md",
    "references/queen-operations.md",
    "references/tl-worker-operations.md",
    "references/diagnostics-retry-reporting.md",
}
REQUIRED_MARKERS = {
    "SKILL.md": (
        "## Autoritätsgrenze",
        "Common Policy",
        "aktuell attestierte Masterjet-/MCP-Generation",
        "Repositorycode ist Ist-Evidenz, nie Policy.",
        "Workerinnen erhalten diesen Leitungsskill nicht.",
        "genau eine Rollenreferenz",
        "Runtime-Migrationspolicy v1",
        "MCP-Koordinationspfad",
        "weder Install noch Activate noch Reload noch Cutover",
        "genau benannte und attestierte Vorgängerversion",
        "Read-only-Live-Preflight",
        "Diagnosegate, reviewed Remediationgate und Aktivierungsgate sind getrennt.",
        "nicht autoritative Evidenz",
        "keine zweite Autorität",
        "Vor belegter Root Cause darf nur reviewte, begrenzte und secretfreie Telemetrie",
        "Real-Live-Fixture dagegen Pflicht",
        "höchstens einmal je evidenzveränderndem, reviewtem Commit",
        "versionierte, geschlossene Fehlerklassifikator",
        "immutable und redigiert",
        "darf kanonische Artefakte nicht mutieren",
        "dritte Klassifikationsarchitektur ist verboten",
        "Cleanup-Ergebnis hat Vorrang vor Primärdiagnose",
        "schließt der Minimalfix die Root Cause, ist er vorzuziehen",
    ),
    "references/common-invariants.md": (
        "Keine numerische globale, Serien- oder Provider-Flottenobergrenze.",
        "aktuell attestierte Ressourcen-, Capability-, Auth-/Quota-, Kosten- und Ruckel-Gates",
        "materialisierter Rolle/Klasse, Principal, Lease und Scope",
        "Entscheidungen, Blocker, Handoffs und Risiken",
        "Kein Übergangspfad, wenn sauberer Neubau oder Cutover möglich ist.",
        "## Runtime-Migrationsvertrag",
        "alleinige verbindliche Quelle",
        "gebundenen deterministischen Dry-run",
        "CAS/Fencing",
        "Transaktionsjournal mit Rollback oder HOLD",
        "secret-freie, begrenzte Telemetrie",
        "echten Consumer-E2E-Vertrag",
        "genau benannte, attestierte Vorgängerversion-Input",
        "Diagnose, reviewed Remediation und Aktivierung bleiben getrennte Gates",
        "nie zur zweiten Autorität",
        "Vor bekannter Root Cause darf nur reviewte, begrenzte und secretfreie Telemetrie",
        "Real-Live-Fixture ist Pflicht vor Aktivierung oder Cutover",
        "Evidenz hat eine definierte Freshness/TTL",
        "versionierter geschlossener Vertrag",
        "Negativmatrix jede unterstützte Fehlerfamilie",
        "früheste rote Schicht beendet den Lauf",
        "Höchstens ein Live- oder Canary-Versuch",
        "immutable, redigierte Pre-Baseline",
        "Ownership unmittelbar vor jeder Mutation",
        "Scope-/Komplexitätsbudget",
        "lokalen getesteten Minimalfix",
        "Canary darf kanonische Artefakte nicht mutieren",
        "dritte Klassifikationsarchitektur ist verboten",
        "Cleanup-Ergebnis hat Vorrang vor Primärdiagnose",
        "Minimalfix die Root Cause, ist er vorzuziehen",
    ),
    "references/queen-operations.md": (
        "Queen plant, delegiert und pflegt Entscheidungen und Pläne.",
        "implementiert, testet, reviewt oder integriert keinen Produktionscode.",
        "Queen → TL → Workerinnen",
        "keine Lifecycle-Ausführungsautorität",
        "Weder Queen noch ihr Fleet-Skill oder MCP-Koordinationspfad darf "
        "Install, Activate, Reload oder Cutover ausführen oder erlauben.",
        "keine Live-Autorität wird aus diesem Dokument abgeleitet.",
        "Diagnosegate, reviewed Remediationgate und Aktivierungsgate",
        "nie zur zweiten Autorität",
        "Real-Live-Fixture ist vor Aktivierung oder Cutover Pflicht",
        "nativen Plattformdiagnostik oder expliziten Userentscheidung",
    ),
    "references/tl-worker-operations.md": (
        "TL startet Workerinnen.",
        "einem Thema und einer Datei",
        "aussagekräftigen Test",
        "Full Suite selten",
        "Topicresume",
        "spawn.requested",
        "kein Handshake je Datagramm",
        "kleine Feature-Änderung und eine Runtime- oder "
        "Installationsmigration sind getrennte Pakete.",
        "Scope-/Budget-Gate",
        "eigenes Voraussetzungspaket",
        "Read-only-Live-Preflight",
        "finalen unabhängigen Review",
        "fokussierten Tests",
        "echten Consumer-E2E-Vertrag",
        "gebundenen Dry-run, CAS/Fencing, Journal, Rollback/HOLD",
        "Workerinnen aktivieren keine ungebundene Migration oder keinen "
        "ungebundenen Cutover.",
        "Diagnosegate, reviewed Remediationgate und Aktivierungsgate",
        "nicht autoritative Evidenz",
        "vor belegter Root Cause nur reviewte, begrenzte und secretfreie Telemetrie",
        "höchstens einen Live- oder Canary-Versuch",
        "nativer Plattformdiagnostik",
        "Negativmatrix für jede unterstützte Fehlerfamilie",
        "immutable, redigierte Pre-Baseline",
        "Foreign Objects bleiben unberührt",
        "Scope-/Komplexitätsbudget",
        "darf kanonische Artefakte nicht mutieren",
        "dritte Klassifikationsarchitektur beauftragt sie nicht",
        "Cleanup-Ergebnis hat Vorrang vor Primärdiagnose",
        "wenn er die Root Cause schließt",
    ),
    "references/diagnostics-retry-reporting.md": (
        "spätestens stündlich",
        "5, 5, 5, 10, 15, 20, 40, 60, 90, 120, 150, 180, 240, 300",
        "agent_assignment_report",
        "assignmentgebunden",
        "ANSI-bereinigt",
        "kein Legacyfallback",
        "kein Grund zum Abbruch",
        "Runtime-Migrationsdiagnose",
        "nur read-only, redigierte Evidenz",
        "Transaktions-ID/Fence, Phase, Fehlerklasse, Rollback- oder "
        "HOLD-Zustand und finale Identität",
        "ohne Secrets oder unbegrenzte Felder",
        "Zwei identische Live-Fehlschläge sperren den dritten Versuch",
        "Diagnostik-, Remediation- und Aktivierungsautorität bleiben getrennt.",
        "nie eine zweite Autorität",
        "Vor bekannter Root Cause darf nur reviewte, begrenzte und secretfreie Telemetrie",
        "genau einen Commit; blinde Wiederholung ist verboten.",
        "Negativmatrix jede unterstützte Fehlerfamilie",
        "früheste rote Schicht beendet den Lauf",
        "Pre-Baseline behauptet er keine Unverändertheit",
        "Evidenz-Freshness/TTL",
        "Real-Live-Fixture ist vor Aktivierung oder Cutover Pflicht",
        "Kompatibilitätsmatrix von Manager-, Runtime- und Client-Versionen",
        "darf kanonische Artefakte nicht mutieren",
        "dritte Klassifikationsarchitektur ist verboten",
        "Cleanup-Ergebnis hat Vorrang vor Primärdiagnose",
        "schließt dieser die Root Cause, ist er vorzuziehen",
    ),
}
FORBIDDEN_LEGACY = (
    "gpt-5.4-mini",
    "gpt-5.3-codex-spark",
    "a1..a100",
    "a-series",
    "u-series",
    "Main instance is the Teamleiterin",
    "10 Bienen",
    "idle_seconds",
    "assign-write",
    "start both",
    "./bin/codex-master-mcp",
    "OpenAI",
    "Claude",
    "Gemini",
    "Ollama",
    "DeepSeek",
    "xhigh",
    "low",
    "medium",
)


def _skill_root() -> Path:
    return Path(os.environ.get("FLEET_SKILL_ROOT", DEFAULT_ROOT))


def _is_inside(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _has_symlink_ancestor(path: Path, root: Path) -> bool:
    current = path
    while current != root:
        if current.is_symlink():
            return True
        current = current.parent
    return root.is_symlink()


def test_the_hive_fleet_router_contract() -> None:
    """Catch a second policy book, unsafe routing, or legacy fleet policy."""
    root = _skill_root()
    repository = root.parents[1]
    router = root / "SKILL.md"
    violations: list[str] = []

    if (repository / "skills" / "codex-master-fleet").exists():
        violations.append("legacy skill tree remains discoverable")

    if not router.is_file() or router.is_symlink():
        violations.append("router must be a regular SKILL.md")
        router_text = ""
    else:
        router_text = router.read_text(encoding="utf-8")

    frontmatter = re.match(r"\A---\n(.*?)\n---\n", router_text, re.DOTALL)
    if frontmatter is None or not re.search(
        r"^name: the-hive-fleet$", frontmatter.group(1), re.MULTILINE
    ):
        violations.append("router frontmatter must expose exactly the-hive-fleet")

    skill_files = list(root.rglob("SKILL.md")) if root.is_dir() else []
    if skill_files != [router]:
        violations.append("skill tree must contain exactly one discoverable SKILL.md")

    if router_text and (
        len(router_text.splitlines()) > 160 or len(router_text.encode()) > 10 * 1024
    ):
        violations.append("router exceeds its 160-line or 10-KiB context budget")

    linked_references = set(
        re.findall(r"\]\((references/[A-Za-z0-9._/-]+)\)", router_text)
    )
    if linked_references != EXPECTED_REFERENCES:
        violations.append(
            f"router references {sorted(linked_references)}, expected {sorted(EXPECTED_REFERENCES)}"
        )

    contract_files = {"SKILL.md": router}
    for relative in EXPECTED_REFERENCES:
        target = root / relative
        contract_files[relative] = target
        if (
            not target.is_file()
            or target.is_symlink()
            or _has_symlink_ancestor(target, root)
        ):
            violations.append(f"{relative} must be a regular non-symlink file")
        if not _is_inside(target.resolve(), repository.resolve()):
            violations.append(f"{relative} escapes the repository")

    for relative, markers in REQUIRED_MARKERS.items():
        target = contract_files[relative]
        text = target.read_text(encoding="utf-8") if target.is_file() else ""
        normalized_text = re.sub(r"\s+", " ", text)
        for marker in markers:
            if re.sub(r"\s+", " ", marker) not in normalized_text:
                violations.append(f"{relative} lacks contract marker: {marker}")

    all_contract_text = "\n".join(
        target.read_text(encoding="utf-8")
        for target in contract_files.values()
        if target.is_file()
    )
    for legacy in FORBIDDEN_LEGACY:
        if legacy.casefold() in all_contract_text.casefold():
            violations.append(f"legacy policy remains discoverable: {legacy}")

    assert not violations, "\n".join(violations)


def test_diagnostics_forbid_abort_from_runtime_silence_or_long_test() -> None:
    """Reject wording that turns normal waiting into permission to abort."""
    diagnostic = _skill_root() / "references" / "diagnostics-retry-reporting.md"
    text = re.sub(r"\s+", " ", diagnostic.read_text(encoding="utf-8"))

    assert (
        "Laufzeit, Schweigen oder ein langer Test sind kein Grund zum Abbruch." in text
    )
    assert "Abbruch nur bei konkreter begründeter Fehlerannahme." in text
    assert "nicht abbrechen zu lassen" not in text


def test_runtime_migration_policy_is_closed_linked_read_only_contract() -> None:
    """Keep the router closed over the canonical migration-policy source."""
    root = _skill_root()
    repository = root.parents[1]
    policy = repository / RUNTIME_MIGRATION_POLICY
    contract_files = {
        "SKILL.md": root / "SKILL.md",
        **{relative: root / relative for relative in EXPECTED_REFERENCES},
    }
    text = {
        relative: path.read_text(encoding="utf-8")
        for relative, path in contract_files.items()
    }

    assert policy.is_file()
    assert RUNTIME_MIGRATION_POLICY_LINK in text["references/common-invariants.md"]
    assert "keine Live-Autorität" in text["SKILL.md"]
    assert "weder Install noch Activate noch Reload noch Cutover" in text["SKILL.md"]
    assert "echten Consumer-E2E-Vertrag" in text["references/common-invariants.md"]
    assert "ungebundene Migration" in text["references/tl-worker-operations.md"]
    assert "Zwei identische Live-Fehlschläge" in text[
        "references/diagnostics-retry-reporting.md"
    ]


def test_runtime_diagnostic_evidence_contract_stays_non_authoritative() -> None:
    """Keep every fleet projection linked and unable to open lifecycle gates."""
    root = _skill_root()
    contract_files = {
        "SKILL.md": root / "SKILL.md",
        **{relative: root / relative for relative in EXPECTED_REFERENCES},
    }
    text = {
        relative: re.sub(r"\s+", " ", path.read_text(encoding="utf-8"))
        for relative, path in contract_files.items()
    }

    assert "Runtime-Migrationspolicy v1" in text["SKILL.md"]
    for relative in EXPECTED_REFERENCES:
        assert RUNTIME_MIGRATION_POLICY_LINK in text[relative]

    combined = " ".join(text.values())
    assert "nicht autoritative Evidenz" in combined
    assert "nie zur zweiten Autorität" in combined
    assert "secretfreie Telemetrie" in combined
    assert "kein Produktaktivierungsgate" in combined
    assert "Installieren, Aktivieren, Beobachten und endgültiges Committen" in combined
    assert "Höchstens ein Live- oder Canary-Versuch" in combined
    assert "blinde Wiederholung ist verboten" in combined
    assert "native Plattformdiagnostik" in combined
    assert "unbekannt bleibt fail-closed" in combined
    assert "früheste rote Schicht beendet den Lauf" in combined
    assert "kanonische Artefakte nicht mutieren" in combined
    assert "dritte Klassifikationsarchitektur ist verboten" in combined
    assert "Cleanup-Ergebnis hat Vorrang vor Primärdiagnose" in combined
    assert "Foreign Objects" in combined
    assert "Kompatibilitätsmatrix" in combined
    assert "Real-Live-Fixture ist vor Aktivierung oder Cutover Pflicht" in combined

    authority_denials = {
        "SKILL.md": "weder Install noch Activate noch Reload noch Cutover",
        "references/common-invariants.md": "erteilen keine Live-Autorität",
        "references/queen-operations.md": "keine Lifecycle-Ausführungsautorität",
        "references/tl-worker-operations.md": "weder Install noch Activate noch Reload noch Cutover",
        "references/diagnostics-retry-reporting.md": "führen weder Install noch Activate noch Reload noch Cutover",
    }
    for relative, marker in authority_denials.items():
        assert marker in text[relative], f"{relative} grants lifecycle authority"


def test_runtime_migration_roadmap_keeps_fixture_and_masterplan_holds_visible() -> (
    None
):
    """Keep the repo plan complete without turning deferred live evidence into a loop."""
    roadmap = Path(__file__).resolve().parents[1] / ROADMAP
    text = re.sub(r"\s+", " ", roadmap.read_text(encoding="utf-8"))

    for marker in (
        "POLICY_MATERIALIZATION_OPEN",
        "DEFERRED_LIVE_FIXTURE",
        "[kanonische maschinenlesbare Policy]"
        "(src/the_hive/markdown/runtime-migration-policy-v1.json)",
        "[Common-Policy-Projektion](src/the_hive/markdown/common.md)",
        "[Policytests](tests/test_runtime_migration_policy.py)",
        "[Fleet-Router-Vertragstests](tests/test_the_hive_fleet_router_contract.py)",
        "read-only Diagnose mit frischer Evidenz",
        "reviewter, bounded Telemetrie ausschließlich als nicht autoritative Evidenz",
        "reviewed Remediation",
        "separates Aktivierungsgate",
        "begrenzte Beobachtung",
        "endgültiges Committen",
        "kein Gate für Policy- oder Diagnoseintegration",
        "Sidecar-Konflikts `HOLD`",
        "Canarys mutieren keine kanonischen Artefakte.",
        "Cleanup-Ergebnis hat Vorrang vor Primärdiagnose.",
        "dritte Klassifikationsarchitektur ist verboten.",
    ):
        assert marker in text
