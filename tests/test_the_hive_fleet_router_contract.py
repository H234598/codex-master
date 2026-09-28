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
    ),
    "references/queen-operations.md": (
        "Queen plant, delegiert und pflegt Entscheidungen und Pläne.",
        "implementiert, testet, reviewt oder integriert keinen Produktionscode.",
        "Queen → TL → Workerinnen",
        "keine Lifecycle-Ausführungsautorität",
        "Weder Queen noch ihr Fleet-Skill oder MCP-Koordinationspfad darf "
        "Install, Activate, Reload oder Cutover ausführen oder erlauben.",
        "keine Live-Autorität wird aus diesem Dokument abgeleitet.",
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
