import os
from pathlib import Path
import re
import subprocess

from codex_master.runtime_layout import RuntimeLayout


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"


def workflow_text() -> str:
    return WORKFLOW.read_text(encoding="utf-8")


def workflow_step_run(name: str) -> str:
    marker = f"      - name: {name}\n"
    following = workflow_text().split(marker, 1)[1]
    step = following.split("\n      - name:", 1)[0]
    indented_run = step.split("        run: |\n", 1)[1]
    return "\n".join(
        line.removeprefix("          ") for line in indented_run.splitlines()
    )


def test_ruff_gate_is_pinned_and_non_mutating() -> None:
    workflow = workflow_text()

    assert "ruff==0.16.3" in workflow
    assert "ruff check --select E4,E7,E9,F --output-format=github ." in workflow
    assert not re.search(r"^\s*run:\s*ruff\s+check\b.*\s--fix(?:\s|$)", workflow, re.MULTILINE)


def test_ci_installs_agent_api_crypto_dependencies_before_collection() -> None:
    workflow = workflow_text()

    dependency_step = workflow.split("      - name: Install test dependencies\n", 1)[1]
    dependency_step = dependency_step.split("\n      - name:", 1)[0]
    assert "PyJWT[crypto]>=2.9,<3" in dependency_step


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


def test_agent_pool_installer_gate_materializes_a_valid_image_for_a_fresh_home(
    tmp_path: Path,
) -> None:
    """Catch a CI change that invokes the image-only wrapper before its image."""

    runner_temp = tmp_path / "runner-temp"
    runner_temp.mkdir(mode=0o700)
    home = tmp_path / "fresh-home"
    home.mkdir(mode=0o700)
    completed = subprocess.run(
        ["bash", "-euo", "pipefail", "-c", workflow_step_run("Check agent pool installer")],
        cwd=ROOT,
        env={
            **os.environ,
            "HOME": str(home),
            "RUNNER_TEMP": str(runner_temp),
            "PYTHONDONTWRITEBYTECODE": "1",
        },
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    ci_home = runner_temp / "codex-agent-pool-ci-home"
    RuntimeLayout.from_runtime_root(
        ci_home / ".local" / "lib" / "codex-master-runtime"
    )
    assert not (ci_home / ".codex-agents-ci").exists()
