from __future__ import annotations

import runpy
from pathlib import Path
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[1]


def seal_runtime_image(root: Path) -> None:
    """Add the real helper and canonical manifest to a private test image."""

    helper = root / "src" / "codex_master" / "_runtime_spawn_helper.so"
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
            str(ROOT / "src" / "codex_master" / "runtime_spawn_helper.c"),
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
        str(ROOT / "scripts" / "codex-master-hive-hourly-probe-install")
    )
    installer["_write_runtime_image_manifest"](root=root)


@pytest.fixture(scope="session")
def runtime_image(tmp_path_factory: pytest.TempPathFactory):
    """Materialize the production Runtime Image contract once for runner tests."""

    from codex_master.runtime_layout import RuntimeLayout

    stage = tmp_path_factory.mktemp("runtime-image") / "codex-master-runtime"
    stage.mkdir(mode=0o700)
    installer = runpy.run_path(
        str(ROOT / "scripts" / "codex-master-hive-hourly-probe-install")
    )
    installer["_build_runtime_image"](repository=ROOT, stage=stage)
    return RuntimeLayout.from_runtime_root(stage)


@pytest.fixture
def runtime_spawn_helper(runtime_image, monkeypatch: pytest.MonkeyPatch):
    """Route runner unit tests through the complete production image contract."""

    import codex_master.runtime_process as runtime_process

    monkeypatch.setattr(
        runtime_process.RuntimeLayout,
        "from_module_path",
        classmethod(lambda _cls, _module_path: runtime_image),
    )
    return runtime_image
