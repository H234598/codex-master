from __future__ import annotations

from pathlib import Path
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def runtime_spawn_helper(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Build the same checked glibc helper that a Runtime Image contains."""

    import codex_master.runtime_process as runtime_process

    helper = tmp_path / "_runtime_spawn_helper.so"
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
            str(ROOT / "src" / "codex_master" / "runtime_spawn_helper.c"),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr
    monkeypatch.setattr(
        runtime_process, "_runtime_spawn_helper_path", lambda _path=None: helper
    )
    return helper
