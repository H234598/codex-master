"""Exercise the repository's scanner configuration with private tool fixtures."""

import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tomllib

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[1]


def _tool(name):
    executable = os.environ.get("THE_HIVE_TEST_" + name.upper()) or shutil.which(name)
    if not executable:
        pytest.skip(f"{name} is not available for the real scanner regression")
    return executable


def _configured_command(tool, driver, targets, root, *, output=None):
    config = tomllib.loads((ROOT / ".qlty/qlty.toml").read_text())
    script = config["plugins"]["definitions"][tool]["drivers"][driver]["script"]
    script = script.replace("${target}", shlex.join(targets))
    if output is not None:
        script = script.replace("${tmpfile}", shlex.quote(str(output)))
    environment = dict(os.environ)
    environment["PATH"] = (
        str(Path(_tool(tool)).parent) + os.pathsep + environment["PATH"]
    )
    return subprocess.run(
        ["/bin/sh", "-c", script],
        cwd=root,
        env=environment,
        capture_output=True,
        text=True,
    )


def test_trivy_skips_generated_mypy_cache_and_keeps_iac_checks(tmp_path):
    executable = _tool("trivy")
    paths = [
        ".mypy_cache/probe/Dockerfile",
        "deployment/Dockerfile",
        ".qlty/active/Dockerfile",
    ]
    for name in paths:
        path = tmp_path / name
        path.parent.mkdir(parents=True)
        path.write_text("FROM alpine:3.20\nUSER root\n")

    def dockerfile_findings(checked):
        assert checked.returncode == 0, checked.stdout + checked.stderr
        report = json.loads(checked.stdout)
        return {
            location["physicalLocation"]["artifactLocation"]["uri"].removeprefix("/")
            for run in report["runs"]
            for result in run.get("results", [])
            if result["ruleId"] == "DS-0002"
            for location in result["locations"]
        }

    baseline = subprocess.run(
        [executable, "config", ".", "--format", "sarif"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
    )
    (tmp_path / "baseline.sarif").write_text(baseline.stdout)
    (tmp_path / "baseline.stderr").write_text(baseline.stderr)
    assert dockerfile_findings(baseline) == set(paths)

    checked = _configured_command("trivy", "config", ["."], tmp_path)
    (tmp_path / "configured.sarif").write_text(checked.stdout)
    (tmp_path / "configured.stderr").write_text(checked.stderr)
    assert dockerfile_findings(checked) == set(paths[1:])
    assert not any(
        location["physicalLocation"]["artifactLocation"]["uri"]
        .lstrip("/")
        .startswith(".mypy_cache/")
        for run in json.loads(checked.stdout)["runs"]
        for result in run.get("results", [])
        for location in result.get("locations", [])
    )


def test_mypy_entrypoints_preserve_findings_and_typed_application_imports(tmp_path):
    executable = _tool("mypy")
    paths = ["bin/probe", "libexec/probe"]
    for name in paths:
        path = tmp_path / name
        path.parent.mkdir(parents=True)
        path.write_text(
            "from app.api import identity\n"
            "value: int = 'wrong'\n"
            "result = identity('wrong')\n"
        )
    package = tmp_path / "src/app"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("")
    (package / "api.py").write_text(
        "def identity(value: int) -> int:\n    return value\n"
    )
    baseline = [executable, "--ignore-missing-imports", "--output", "json", *paths]
    collided = subprocess.run(baseline, cwd=tmp_path, capture_output=True, text=True)
    assert collided.returncode == 2
    assert 'Duplicate module named "__main__"' in collided.stdout
    renamed = subprocess.run(
        [*baseline[:1], "--scripts-are-modules", *baseline[1:]],
        cwd=tmp_path,
        capture_output=True,
        text=True,
    )
    assert renamed.returncode == 2
    assert 'Duplicate module named "probe"' in renamed.stdout

    config = tomllib.loads((ROOT / ".qlty/qlty.toml").read_text())
    driver = config["plugins"]["definitions"]["mypy"]["drivers"]["format"]
    batches = [paths] if driver["batch"] else [[path] for path in paths]
    findings = []
    for batch in batches:
        checked = _configured_command("mypy", "format", batch, tmp_path)
        assert checked.returncode == 1, checked.stdout + checked.stderr
        findings.extend(json.loads(line) for line in checked.stdout.splitlines())
    for path in paths:
        assert {item["code"] for item in findings if item["file"] == path} == {
            "assignment",
            "arg-type",
        }

    # An explicit package module keeps the same qualified name with this config.
    ordinary = subprocess.run(
        [executable, "-v", "src/app/api.py"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
    )
    configured = _configured_command(
        "mypy", "format", ["-v", "src/app/api.py"], tmp_path
    )
    assert ordinary.returncode == configured.returncode == 0
    assert "module='app.api'" in ordinary.stderr
    assert "module='app.api'" in configured.stderr


def test_bandit_assert_exception_keeps_production_and_other_test_rules(tmp_path):
    executable = _tool("bandit")
    target = "tests/test_runtime_lifecycle_service.py"
    other_test = "tests/test_other.py"
    production = "src/test_runtime_lifecycle_service.py"
    sources = {
        target: "import subprocess\nassert True\nsubprocess.run(['echo', 'test'])\n",
        other_test: "assert True\n",
        production: "assert True\n",
    }
    for name, body in sources.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body)
    (tmp_path / ".bandit.yaml").write_bytes((ROOT / ".bandit.yaml").read_bytes())
    raw = subprocess.run(
        [executable, "--exit-zero", "--format", "json", *sources],
        cwd=tmp_path,
        capture_output=True,
        text=True,
    )
    assert raw.returncode == 0
    original = json.loads(raw.stdout)
    assert not original["errors"]
    assert any(item["test_id"] == "B101" for item in original["results"])

    output = tmp_path / "bandit-results.json"
    checked = _configured_command(
        "bandit", "lint", list(sources), tmp_path, output=output
    )
    assert checked.returncode == 0, checked.stdout + checked.stderr
    result = json.loads(output.read_text())
    assert not result["errors"]

    def rules(document, path):
        return {
            item["test_id"]
            for item in document["results"]
            if item["filename"].removeprefix("./") == path
        }

    assert "B101" in rules(original, target)
    assert "B101" not in rules(result, target)
    assert rules(result, target) == rules(original, target) - {"B101"}
    assert {"B404", "B603", "B607"}.issubset(rules(result, target))
    assert "B101" in rules(result, production)
    assert "B101" in rules(result, other_test)


def test_mypy_module_package_findings_are_retained_by_qlty(tmp_path):
    executable = _tool("qlty")
    paths = ["src/the_hive/selection.py", "src/the_hive/selection/__init__.py"]
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    config = tmp_path / ".qlty"
    config.mkdir()
    (config / "qlty.toml").write_bytes((ROOT / ".qlty/qlty.toml").read_bytes())
    for name in paths:
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("value: int = 'wrong'\n")
    (tmp_path / "src/the_hive/__init__.py").write_text("")
    result = subprocess.run(
        [
            executable,
            "check",
            "--filter=mypy",
            "--no-fix",
            "--no-cache",
            "--sarif",
            "--no-progress",
            "--print-errors",
            "--no-upgrade-check",
            "--skip-source-fetch",
            "--",
            *paths,
        ],
        cwd=tmp_path,
        capture_output=True,
        text=True,
    )
    (tmp_path / "check.sarif").write_text(result.stdout)
    (tmp_path / "check.stderr").write_text(result.stderr)
    assert result.returncode == 1, result.stdout + result.stderr
    report = json.loads(result.stdout)
    retained = []
    for run in report["runs"]:
        assert all(item["executionSuccessful"] for item in run["invocations"])
        for finding in run["results"]:
            location = finding["locations"][0]["physicalLocation"]
            retained.append(
                (
                    location["artifactLocation"]["uri"],
                    location["region"]["startLine"],
                    finding["ruleId"].removeprefix("mypy:"),
                )
            )
    produced = []
    targets = []
    for record in (tmp_path / ".qlty/out").glob("invoke-*.yaml"):
        document = yaml.safe_load(record.read_text())
        assert document["driverName"] == "format"
        assert document["exitResult"] == "EXIT_RESULT_SUCCESS"
        targets.extend(document["targetPaths"])
        produced.extend(
            (item["file"], item["line"], item["code"])
            for line in document["stdout"].splitlines()
            if line.startswith("{")
            for item in [json.loads(line)]
        )
    expected = [(path, 1, "assignment") for path in paths]
    assert sorted(targets) == sorted(paths)
    assert sorted(produced) == sorted(retained) == sorted(expected)
