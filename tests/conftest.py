from __future__ import annotations

import os
import runpy
import stat
from pathlib import Path
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[1]
_TEST_MANIFEST_COMMIT = "a" * 40


def _write_required_codex_skill_fixture(home: Path) -> dict[str, bytes]:
    expected = {
        ".agents/skills/code-review/SKILL.md": b"# Code review\n",
        ".agents/skills/code-review/references/auth-recovery.md": b"# Recovery\n",
        ".agents/skills/code-review/references/cli-workflows.md": b"# CLI workflow\n",
        ".agents/skills/autofix/SKILL.md": b"# Autofix\n",
        ".agents/skills/autofix/github.md": b"# GitHub reference\n",
        ".agents/skills/find-skills/SKILL.md": b"# Find skills\n",
    }
    for name, content in expected.items():
        path = home / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    return expected


def regular_home_files_for_test(home: Path) -> list[Path]:
    """List every regular file without following or silently skipping symlinks."""
    if not stat.S_ISDIR(home.lstat().st_mode):
        raise AssertionError(f"untrusted test home: {home}")

    def raise_walk_error(error: OSError) -> None:
        raise error

    files: list[Path] = []
    for directory, names, leaves in os.walk(
        home, followlinks=False, onerror=raise_walk_error
    ):
        for name in (*names, *leaves):
            path = Path(directory) / name
            mode = path.lstat().st_mode
            if stat.S_ISLNK(mode):
                raise AssertionError(f"unexpected symlink in test home: {path}")
            if stat.S_ISREG(mode):
                files.append(path)
            elif not stat.S_ISDIR(mode):
                raise AssertionError(f"unexpected entry in test home: {path}")
    return sorted(files)


@pytest.fixture
def hermetic_codex_skill_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    home = tmp_path / "codex-skill-source"
    home.mkdir(mode=0o700)
    _write_required_codex_skill_fixture(home)
    monkeypatch.setenv("HOME", str(home))
    return home


def seal_runtime_image(root: Path, *, commit: str = _TEST_MANIFEST_COMMIT) -> None:
    """Add the real helper and canonical manifest to a private test image."""

    witness = root / "src" / "the_hive" / "dynamic_pool.py"
    if not witness.exists():
        witness.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        witness.write_bytes(
            (ROOT / "src" / "the_hive" / "dynamic_pool.py").read_bytes()
        )
        witness.chmod(0o644)
    helper = root / "src" / "the_hive" / "_runtime_spawn_helper.so"
    helper.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    completed = subprocess.run(
        [
            "/usr/bin/cc",
            "-std=c11",
            "-D_GNU_SOURCE",
            "-fPIC",
            "-shared",
            "-Werror",
            "-Wall",
            "-Wextra",
            "-o",
            str(helper),
            str(ROOT / "src" / "the_hive" / "runtime_spawn_helper.c"),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr
    helper.chmod(0o755)
    current = helper.parent
    while current != root:
        current.chmod(0o700)
        current = current.parent
    installer = runpy.run_path(
        str(ROOT / "scripts" / "the-hive-hive-hourly-probe-install")
    )
    installer["_write_runtime_image_manifest"](root=root, commit=commit)


@pytest.fixture(scope="session")
def runtime_image(tmp_path_factory: pytest.TempPathFactory):
    """Materialize the production Runtime Image contract once for runner tests."""

    from the_hive.runtime_layout import RuntimeLayout

    stage = tmp_path_factory.mktemp("runtime-image") / "the-hive-runtime"
    stage.mkdir(mode=0o700)
    installer = runpy.run_path(
        str(ROOT / "scripts" / "the-hive-hive-hourly-probe-install")
    )
    installer["_build_runtime_image"](
        repository=ROOT, stage=stage, commit=_TEST_MANIFEST_COMMIT
    )
    return RuntimeLayout.from_runtime_root(stage)


@pytest.fixture
def runtime_spawn_helper(runtime_image, monkeypatch: pytest.MonkeyPatch):
    """Route runner unit tests through the complete production image contract."""

    import the_hive.runtime_process as runtime_process

    monkeypatch.setattr(
        runtime_process.RuntimeLayout,
        "from_module_path",
        classmethod(lambda _cls, _module_path: runtime_image),
    )
    return runtime_image
