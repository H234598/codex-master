import json
from pathlib import Path

import pytest

from codex_master.remote_queen_bootstrap_cli import main


FIXTURE_DIR = Path(__file__).parent / "fixtures" / "remote_queen_bootstrap"


def _run_plan(target, fixture, capsys):
    exit_code = main(["plan", target, "--fixture", str(fixture)])
    return exit_code, capsys.readouterr()


def test_plan_cli_does_not_mutate_fixture_and_prints_canonical_plan(capsys):
    fixture = FIXTURE_DIR / "host-empty.json"
    before = fixture.read_bytes()

    exit_code, captured = _run_plan("queen@example.test", fixture, capsys)

    assert exit_code == 0
    assert captured.err == ""
    assert json.loads(captured.out)["schema_version"] == "RemoteQueenBootstrapPlanV1"
    assert len(json.loads(captured.out)["steps"]) == 5
    assert fixture.read_bytes() == before


@pytest.mark.parametrize(
    "target",
    ["-oProxyCommand=x", "-h", "--help", "--ProxyCommand=x"],
)
def test_plan_cli_rejects_option_like_ssh_target(target, capsys):
    exit_code, captured = _run_plan(
        target, FIXTURE_DIR / "host-empty.json", capsys
    )

    assert exit_code == 2
    assert captured.out == ""
    assert captured.err == "RQ_E_SSH_TARGET_INVALID\n"
    assert target not in captured.err


def test_plan_cli_rejects_contradictory_fixture_without_mutation(capsys):
    fixture = FIXTURE_DIR / "host-contradictory.json"
    before = fixture.read_bytes()

    exit_code, captured = _run_plan("queen@example.test", fixture, capsys)

    assert exit_code == 2
    assert captured.out == ""
    assert "RQ_E_PLAN_INCONSISTENT" in captured.err
    assert fixture.read_bytes() == before


def test_plan_cli_rejects_malformed_object_id_without_traceback(tmp_path, capsys):
    payload = json.loads((FIXTURE_DIR / "host-empty.json").read_text(encoding="utf-8"))
    payload["object_states"][0]["object_id"] = []
    fixture = tmp_path / "malformed.json"
    fixture.write_text(json.dumps(payload), encoding="utf-8")

    exit_code, captured = _run_plan("queen@example.test", fixture, capsys)

    assert exit_code == 2
    assert captured.out == ""
    assert captured.err == "RQ_E_PLAN_INCONSISTENT\n"
