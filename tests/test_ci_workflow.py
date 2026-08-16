from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"


def workflow_text() -> str:
    return WORKFLOW.read_text(encoding="utf-8")


def test_ruff_gate_is_pinned_and_non_mutating() -> None:
    workflow = workflow_text()

    assert "ruff==0.16.3" in workflow
    assert "ruff check --select E4,E7,E9,F --output-format=github ." in workflow
    assert not re.search(r"^\s*run:\s*ruff\s+check\b.*\s--fix(?:\s|$)", workflow, re.MULTILINE)


def test_manpage_gate_builds_and_renders_repository_source() -> None:
    workflow = workflow_text()

    assert "sudo apt-get install --no-install-recommends --yes groff-base" in workflow
    assert './scripts/codex-master-manpage build --output-dir "${RUNNER_TEMP}/codex-master-man"' in workflow
    assert "groff -man -Tutf8 man/man1/codex-master-mcp.1 >/dev/null" in workflow


def test_external_actions_remain_full_sha_pinned_with_read_only_permissions() -> None:
    workflow = workflow_text()
    external_uses = re.findall(
        r"^\s*uses:\s*([^@\s]+)@([0-9A-Za-z._-]+)",
        workflow,
        flags=re.MULTILINE,
    )

    assert external_uses
    assert "permissions:\n  contents: read" in workflow
    assert "secrets." not in workflow
    assert all(
        action.startswith(("./", ".github/")) or re.fullmatch(r"[0-9a-f]{40}", ref)
        for action, ref in external_uses
    )
