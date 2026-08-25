"""Contract gate for the canonical codex-master-fleet skill router."""

from __future__ import annotations

import os
import re
from pathlib import Path


DEFAULT_ROOT = Path(__file__).resolve().parents[1] / "skills" / "codex-master-fleet"
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
    ),
    "references/common-invariants.md": (
        "Keine numerische globale, Serien- oder Provider-Flottenobergrenze.",
        "aktuell attestierte Ressourcen-, Capability-, Auth-/Quota-, Kosten- und Ruckel-Gates",
        "materialisierter Rolle/Klasse, Principal, Lease und Scope",
        "Entscheidungen, Blocker, Handoffs und Risiken",
        "Kein Übergangspfad, wenn sauberer Neubau oder Cutover möglich ist.",
    ),
    "references/queen-operations.md": (
        "Queen plant, delegiert und pflegt Entscheidungen und Pläne.",
        "implementiert, testet, reviewt oder integriert keinen Produktionscode.",
        "Queen → TL → Workerinnen",
        "Lifecycle-Mutationen sind Queen-only.",
    ),
    "references/tl-worker-operations.md": (
        "TL startet Workerinnen.",
        "einem Thema und einer Datei",
        "aussagekräftigen Test",
        "Full Suite selten",
        "Topicresume",
        "spawn.requested",
        "kein Handshake je Datagramm",
    ),
    "references/diagnostics-retry-reporting.md": (
        "spätestens stündlich",
        "5, 5, 5, 10, 15, 20, 40, 60, 90, 120, 150, 180, 240, 300",
        "agent_assignment_report",
        "assignmentgebunden",
        "ANSI-bereinigt",
        "kein Legacyfallback",
        "kein Grund zum Abbruch",
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


def test_codex_master_fleet_router_contract() -> None:
    """Catch a second policy book, unsafe routing, or legacy fleet policy."""
    root = _skill_root()
    repository = root.parents[1]
    router = root / "SKILL.md"
    violations: list[str] = []

    if not router.is_file() or router.is_symlink():
        violations.append("router must be a regular SKILL.md")
        router_text = ""
    else:
        router_text = router.read_text(encoding="utf-8")

    frontmatter = re.match(r"\A---\n(.*?)\n---\n", router_text, re.DOTALL)
    if frontmatter is None or not re.search(
        r"^name: codex-master-fleet$", frontmatter.group(1), re.MULTILINE
    ):
        violations.append("router frontmatter must expose exactly codex-master-fleet")

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
