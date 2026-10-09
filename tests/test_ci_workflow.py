import json
import os
from pathlib import Path
import re
import shutil
import subprocess

import pytest

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


def test_plugin_manifest_gate_requires_the_hive_identity_without_a_legacy_alias() -> (
    None
):
    step = workflow_step_run("Validate plugin manifests")

    assert 'plugin["name"] == "the-hive"' in step
    assert 'app["apps"]["the-hive"]' in step
    assert "codex-master" not in step


def test_cli_wrapper_syntax_gate_covers_the_stable_hook_launcher() -> None:
    assert (
        "run: bash -n ./bin/the-hive-mcp ./bin/the-hive-mcp-stable "
        "./bin/the-hive-plugin-hook-stable"
    ) in workflow_text()


def test_manpage_gate_builds_and_renders_repository_source() -> None:
    workflow = workflow_text()

    assert "sudo apt-get install --no-install-recommends --yes groff-base" in workflow
    assert './scripts/the-hive-manpage build --output-dir "${RUNNER_TEMP}/the-hive-man"' in workflow
    assert "groff -man -Tutf8 man/man1/the-hive-mcp.1 >/dev/null" in workflow


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


def test_agent_pool_installer_gate_reports_the_runtime_lifecycle_boundary(
    tmp_path: Path,
) -> None:
    """The source-only wrapper must preserve its explicit lifecycle boundary."""

    runner_temp = tmp_path / "runner-temp"
    runner_temp.mkdir(mode=0o700)
    home = tmp_path / "fresh-home"
    home.mkdir(mode=0o700)
    checkout = tmp_path / "clean-checkout"
    subprocess.run(
        ["git", "clone", "--no-hardlinks", "--quiet", str(ROOT), str(checkout)],
        check=True,
    )
    shutil.copytree(
        ROOT,
        checkout,
        dirs_exist_ok=True,
        ignore=shutil.ignore_patterns(".git", ".local", ".pytest_cache", "__pycache__"),
    )
    subprocess.run(
        ["git", "-C", str(checkout), "add", "--all"],
        check=True,
    )
    subprocess.run(
        [
            "git", "-C", str(checkout), "-c", "user.name=CI workflow test",
            "-c", "user.email=ci-workflow-test@example.invalid", "commit",
            "--no-gpg-sign", "--allow-empty", "--quiet", "-m", "test fixture",
        ],
        check=True,
    )
    completed = subprocess.run(
        ["bash", "-euo", "pipefail", "-c", workflow_step_run("Check agent pool installer")],
        cwd=checkout,
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

    ci_home = runner_temp / "codex-agent-pool-ci-home"
    assert completed.returncode == 0, completed.stderr
    assert completed.stderr == ""
    assert json.loads(completed.stdout) == {
        "raw_output": "not_returned",
        "status": "runtime_lifecycle_cutover_required",
    }
    assert not (ci_home / ".local").exists()


@pytest.mark.parametrize(
    ("exit_code", "payload", "stderr", "mutate"),
    (
        (0, {"status": "runtime_lifecycle_cutover_required", "raw_output": "not_returned"}, "", False),
        (2, {"status": "runtime_lifecycle_cutover_required", "raw_output": "not_returned"}, "", False),
        (1, {"status": "installed", "raw_output": "not_returned"}, "", False),
        (1, {"status": "runtime_lifecycle_cutover_required", "raw_output": "not_returned"}, "unexpected stderr", False),
        (1, {"status": "runtime_lifecycle_cutover_required", "raw_output": "not_returned"}, "", True),
    ),
)
def test_agent_pool_ci_gate_rejects_wrong_exit_payload_stderr_or_mutation(
    tmp_path: Path, exit_code: int, payload: dict[str, str], stderr: str, mutate: bool,
) -> None:
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    wrapper = scripts / "the-hive-hive-hourly-probe-install"
    wrapper.write_text(
        "#!/usr/bin/env python3\n"
        "import pathlib, sys\n"
        + ("pathlib.Path(sys.argv[2], '.local').mkdir()\n" if mutate else "")
        + f"print({json.dumps(payload)!r})\n"
        + f"sys.stderr.write({stderr!r})\n"
        + f"raise SystemExit({exit_code})\n",
        encoding="utf-8",
    )
    wrapper.chmod(0o700)
    runner_temp = tmp_path / "runner-temp"
    runner_temp.mkdir()
    completed = subprocess.run(
        ["bash", "-euo", "pipefail", "-c", workflow_step_run("Check agent pool installer")],
        cwd=tmp_path,
        env={**os.environ, "RUNNER_TEMP": str(runner_temp)},
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode != 0
