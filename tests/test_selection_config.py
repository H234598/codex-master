from pathlib import Path
import json
import os

import pytest

from codex_master.selection import AdmissionMode
from codex_master.selection.config import SelectionConfigError, load_selection_policy


ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "examples/codex-selection-policy.json"


def load_payload() -> dict[str, object]:
    return json.loads(POLICY.read_text(encoding="utf-8"))


def write_policy(tmp_path: Path, payload: dict[str, object], name: str = "policy.json") -> Path:
    path = tmp_path / name
    path.write_text(json.dumps(payload), encoding="utf-8")
    os.chmod(path, 0o600)
    return path


def test_loader_maps_private_policy_to_closed_typed_core(tmp_path: Path) -> None:
    config = load_selection_policy(write_policy(tmp_path, load_payload()))

    assert config.mode is AdmissionMode.SHADOW
    assert config.selection_policy().sp0 is False
    assert config.selection_policy().sp3 is False
    assert config.allows_pilot(teamleader="synthetic-teamlead", account="synthetic-account-a", operation="assign") is False
    public = config.public()
    assert public["account_policy_count"] == 1
    assert "synthetic-account-a" not in str(public)
    assert config.digest.startswith("sha256:")


def test_enforced_mode_still_requires_allowlists_and_kill_switch(tmp_path: Path) -> None:
    payload = load_payload()
    payload["selection"]["mode"] = "enforced"
    config = load_selection_policy(write_policy(tmp_path, payload))
    assert config.allows_pilot(teamleader="synthetic-teamlead", account="synthetic-account-a", operation="assign") is True
    assert config.allows_pilot(teamleader="wrong", account="synthetic-account-a", operation="assign") is False

    payload["selection"]["kill_switch"] = True
    killed = load_selection_policy(write_policy(tmp_path, payload, "killed.json"))
    assert killed.allows_pilot(teamleader="synthetic-teamlead", account="synthetic-account-a", operation="assign") is False


@pytest.mark.parametrize(
    "mutator",
    [
        lambda payload: payload.update({"unexpected": True}),
        lambda payload: payload["features"].update({"unknown": True}),
        lambda payload: payload["account_allowlist"].append("synthetic-account-a"),
        lambda payload: payload["selection"].update({"mode": "unknown"}),
    ],
)
def test_loader_rejects_unknown_invalid_or_duplicate_policy_content(tmp_path: Path, mutator) -> None:
    payload = load_payload()
    mutator(payload)
    with pytest.raises(SelectionConfigError):
        load_selection_policy(write_policy(tmp_path, payload))


def test_loader_rejects_symlink_and_hardlink_policy_files(tmp_path: Path) -> None:
    source = write_policy(tmp_path, load_payload(), "source.json")
    symlink = tmp_path / "symlink.json"
    hardlink = tmp_path / "hardlink.json"
    symlink.symlink_to(source)
    os.link(source, hardlink)
    with pytest.raises(SelectionConfigError, match="invalid_selection_policy_path"):
        load_selection_policy(symlink)
    with pytest.raises(SelectionConfigError, match="invalid_selection_policy_file"):
        load_selection_policy(hardlink)
