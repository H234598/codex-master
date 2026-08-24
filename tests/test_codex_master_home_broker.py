import ast
import runpy
import stat
from pathlib import Path

import pytest


ENTRYPOINT = Path(__file__).parents[1] / "bin" / "codex-master-home-broker"


def _require_entrypoint():
    assert ENTRYPOINT.is_file(), f"missing entrypoint: {ENTRYPOINT}"
    return ENTRYPOINT


def test_entrypoint_has_shebang_and_owner_execute_only():
    entrypoint = _require_entrypoint()
    mode = entrypoint.stat().st_mode

    assert entrypoint.read_text().splitlines()[0] == "#!/usr/bin/python3"
    assert mode & stat.S_IXUSR
    assert not mode & (stat.S_IXGRP | stat.S_IXOTH)


def test_runpy_non_main_returns_main_without_exiting():
    entrypoint = _require_entrypoint()
    namespace = runpy.run_path(str(entrypoint), run_name="entrypoint")

    assert callable(namespace["main"])


def test_main_returns_inert_exit_code():
    entrypoint = _require_entrypoint()
    namespace = runpy.run_path(str(entrypoint), run_name="entrypoint")

    assert namespace["main"]() == 78


def test_runpy_main_exits_with_inert_exit_code():
    entrypoint = _require_entrypoint()

    with pytest.raises(SystemExit) as raised:
        runpy.run_path(str(entrypoint), run_name="__main__")

    assert raised.value.code == 78


def test_entrypoint_has_no_imports():
    entrypoint = _require_entrypoint()
    tree = ast.parse(entrypoint.read_text())

    assert not any(
        isinstance(node, (ast.Import, ast.ImportFrom)) for node in ast.walk(tree)
    )


def test_entrypoint_text_has_no_live_broker_behaviors():
    entrypoint = _require_entrypoint()
    source = entrypoint.read_text()

    for forbidden in (
        "__import__",
        "open(",
        "Socket",
        "Broker",
        "Server",
        "Lifecycle",
        "systemd",
        "Install",
        "Live",
    ):
        assert forbidden not in source
