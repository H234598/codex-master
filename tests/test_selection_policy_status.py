from pathlib import Path
import json
from unittest.mock import Mock, patch

from codex_master import server


ROOT = Path(__file__).resolve().parents[1]


def test_selection_policy_default_path_is_hive_resource() -> None:
    assert server.SELECTION_POLICY_FILE.relative_to(server.STATE_ROOT) == Path(
        "hive/resources/selection-policy.json"
    )


def test_selection_policy_status_is_closed_when_file_is_missing(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(server, "SELECTION_POLICY_FILE", tmp_path / "selection-policy.json")

    result = server.selection_policy_status()

    assert result == {
        "ok": False,
        "policy_state": "missing",
        "mode": "disabled",
        "kill_switch": True,
        "reason_code": "selection_policy_missing",
        "policy_file": "not_returned",
        "raw_output": "not_returned",
    }


def test_selection_policy_status_is_secret_free_when_loaded(tmp_path: Path, monkeypatch) -> None:
    path = tmp_path / "selection-policy.json"
    path.write_text((ROOT / "examples/codex-selection-policy.json").read_text(encoding="utf-8"), encoding="utf-8")
    monkeypatch.setattr(server, "SELECTION_POLICY_FILE", path)

    result = server.selection_policy_status()

    assert result["ok"] is True
    assert result["policy_state"] == "loaded"
    assert result["mode"] == "shadow"
    assert result["account_policy_count"] == 1
    assert "synthetic-account-a" not in json.dumps(result, sort_keys=True)
    assert result["policy_file"] == "not_returned"


def test_selection_policy_status_fails_closed_for_invalid_content(tmp_path: Path, monkeypatch) -> None:
    path = tmp_path / "selection-policy.json"
    path.write_text('{"schema_version": 1, "unexpected": true}', encoding="utf-8")
    monkeypatch.setattr(server, "SELECTION_POLICY_FILE", path)

    result = server.selection_policy_status()

    assert result["ok"] is False
    assert result["policy_state"] == "invalid"
    assert result["kill_switch"] is True
    assert result["reason_code"] == "selection_policy_invalid"


def test_selection_policy_status_is_available_through_main_cli(tmp_path: Path, monkeypatch, capsys) -> None:
    monkeypatch.setattr(server, "SELECTION_POLICY_FILE", tmp_path / "selection-policy.json")

    assert server._main_cli_impl(["selection-policy-status"]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["policy_state"] == "missing"
    assert output["kill_switch"] is True


def test_configured_policy_caps_preview_features_and_mode(tmp_path: Path, monkeypatch) -> None:
    payload = json.loads((ROOT / "examples/codex-selection-policy.json").read_text(encoding="utf-8"))
    payload["features"]["sp3_fairness"] = True
    policy_path = tmp_path / "selection-policy.json"
    policy_path.write_text(json.dumps(payload), encoding="utf-8")
    monkeypatch.setattr(server, "SELECTION_POLICY_FILE", policy_path)
    inventory = server._legacy_inventory()
    fleet_service = Mock()
    fleet_service.load.return_value = server.FleetSnapshot(1, 7, (), ())

    with patch.object(server, "published_agent_inventory", return_value=(inventory, False)), patch.object(
        server, "_readonly_fleet_service", return_value=fleet_service
    ), patch.object(server, "agent_auth_status", return_value={"authenticated": True}), patch.object(
        server, "agent_lease_status", return_value={"state": "unclaimed"}
    ), patch.object(server, "read_codex_usage_snapshot", return_value={}):
        result = server.fleet_selection_preview(
            series="a", task_kind="simple", admission_mode="enforced", sp3=True
        )

    assert result["configured_policy"]["state"] == "loaded"
    assert result["selection_policy"]["sp3"] is True
    assert result["admission"]["mode"] == "shadow"
    assert result["admission"]["executable"] is False


def test_configured_policy_kill_switch_caps_preview_to_off(tmp_path: Path, monkeypatch) -> None:
    payload = json.loads((ROOT / "examples/codex-selection-policy.json").read_text(encoding="utf-8"))
    payload["features"]["sp3_fairness"] = True
    payload["selection"]["kill_switch"] = True
    policy_path = tmp_path / "selection-policy.json"
    policy_path.write_text(json.dumps(payload), encoding="utf-8")
    monkeypatch.setattr(server, "SELECTION_POLICY_FILE", policy_path)
    inventory = server._legacy_inventory()
    fleet_service = Mock()
    fleet_service.load.return_value = server.FleetSnapshot(1, 7, (), ())

    with patch.object(server, "published_agent_inventory", return_value=(inventory, False)), patch.object(
        server, "_readonly_fleet_service", return_value=fleet_service
    ), patch.object(server, "agent_auth_status", return_value={"authenticated": True}), patch.object(
        server, "agent_lease_status", return_value={"state": "unclaimed"}
    ), patch.object(server, "read_codex_usage_snapshot", return_value={}):
        result = server.fleet_selection_preview(
            series="a", task_kind="simple", admission_mode="enforced", sp3=True
        )

    assert result["configured_policy"]["kill_switch"] is True
    assert result["selection_policy"]["sp3"] is False
    assert result["admission"]["mode"] == "off"
