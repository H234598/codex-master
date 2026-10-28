from __future__ import annotations

import json

import pytest

from the_hive import server


def test_user_runtime_cli_refuses_root_gate_install(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert not hasattr(server, "install_resource_scope_gate")
    assert server.main_cli(["install-resource-scope-gate"]) == 1
    assert json.loads(capsys.readouterr().out) == {
        "error": "resource_scope_gate_root_consumer_required"
    }


def test_user_runtime_cli_does_not_accept_a_target_override(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as failure:
        server.main_cli(["install-resource-scope-gate", "--target", "/tmp/gate"])
    assert failure.value.code == 2
    assert "unrecognized arguments" in capsys.readouterr().err
