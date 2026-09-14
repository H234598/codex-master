import ast
import runpy
import stat
from pathlib import Path

import pytest

SCRIPT = Path(__file__).parents[1] / "bin" / "codex-master-home-broker"


def _adapter() -> dict[str, object]:
    assert SCRIPT.is_file(), "broker adapter is missing"
    return runpy.run_path(str(SCRIPT), run_name="a3c_adapter_test")


def test_raw_start_surface_is_absent_and_binary_is_inert() -> None:
    namespace = _adapter()

    assert "start_broker" not in namespace
    assert namespace["main"]() == namespace["INERT_EXIT_CODE"] == 78
    assert SCRIPT.read_text(encoding="utf-8").splitlines()[0] == "#!/usr/bin/python3"
    assert stat.S_IMODE(SCRIPT.stat().st_mode) == 0o755
    tree = ast.parse(SCRIPT.read_text(encoding="utf-8"), filename=str(SCRIPT))
    forbidden_names = {
        "start_broker",
        "attest_kernel_peer",
        "build_broker_system_plan",
        "BrokerSystemBoundary",
        "compare_and_start",
    }
    defined = {
        node.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
    }
    imported = {
        alias.asname or alias.name.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in node.names
    }
    called = {
        node.func.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }

    assert defined.isdisjoint(forbidden_names)
    assert imported.isdisjoint(forbidden_names)
    assert called.isdisjoint(forbidden_names)
    with pytest.raises(SystemExit) as exited:
        runpy.run_path(str(SCRIPT), run_name="__main__")
    assert exited.value.code == 78
