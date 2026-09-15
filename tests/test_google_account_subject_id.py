"""Public redaction contract for the synthetic-subject-id goblin.

The defect these tests protect against is a second identity implementation or
an adapter that emits a subject identifier instead of the authority status.
"""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys

from the_hive import google_account_manager_cli as cli


_ROOT = Path(__file__).resolve().parents[1]
_SCRIPT = _ROOT / "scripts" / "google-account-subject-id"


class _Service:
    def __init__(self, result: dict[str, str]) -> None:
        self.result = result
        self.calls = 0

    def subject_status(self) -> dict[str, str]:
        self.calls += 1
        return self.result


def test_subject_id_uses_the_same_authority_status_facade(monkeypatch, capsys) -> None:
    service = _Service({"status": "bound"})
    monkeypatch.setattr(cli, "GoogleInventoryReadonlyControlService", lambda: service)

    assert cli.subject_id_main([]) == 0

    assert json.loads(capsys.readouterr().out) == {"status": "bound"}
    assert service.calls == 1


def test_subject_id_never_reflects_identity_or_invalid_argument(
    monkeypatch, capsys
) -> None:
    service = _Service({"status": "bound", "unexpected_identity": "redacted-marker"})
    monkeypatch.setattr(cli, "GoogleInventoryReadonlyControlService", lambda: service)

    assert cli.subject_id_main([]) == 1
    sensitive = capsys.readouterr()
    assert sensitive.out == ""
    assert sensitive.err.strip() == "inventory.readonly_control_unavailable"

    assert cli.subject_id_main(["--unexpected", "blocked"]) == 1
    invalid = capsys.readouterr()
    assert invalid.out == ""
    assert invalid.err.strip() == "inventory.readonly_control_request_invalid"


def test_subject_id_goblin_fails_closed_without_private_configuration() -> None:
    result = subprocess.run(
        [sys.executable, str(_SCRIPT)],
        cwd=_ROOT,
        env={"PYTHONPATH": str(_ROOT / "src")},
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 1
    assert result.stdout == ""
    assert result.stderr.strip() == "inventory.readonly_control_unavailable"


def test_subject_id_goblin_redacts_package_import_failure() -> None:
    result = subprocess.run(
        [sys.executable, str(_SCRIPT)],
        cwd=_ROOT,
        env={},
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 1
    assert result.stdout == ""
    assert result.stderr.strip() == "inventory.readonly_control_unavailable"
