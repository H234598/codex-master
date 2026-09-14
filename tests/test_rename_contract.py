from __future__ import annotations

import copy
from importlib.resources import files
import json
from pathlib import Path
import subprocess
import tarfile
from io import BytesIO

import pytest

from the_hive.rename_contract import (
    RenameContractError,
    RenameReleaseValidator,
    load_rename_matrix,
    parse_rename_matrix,
)


ROOT = Path(__file__).resolve().parents[1]
D73_BASE = "f6f9348a4348d1a18bb3c4b591a93c393dfda838"


def _commit_tree(root: Path) -> None:
    subprocess.run(["git", "init", "--quiet"], cwd=root, check=True)
    subprocess.run(["git", "add", "."], cwd=root, check=True)
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=TH-R1 test",
            "-c",
            "user.email=th-r1@example.invalid",
            "commit",
            "--quiet",
            "-m",
            "contract fixture",
        ],
        cwd=root,
        check=True,
    )


def _write_target_ready_tree(root: Path) -> None:
    matrix = load_rename_matrix()
    for family in matrix.bounded_families:
        for template in family.target_path_templates:
            path = root / matrix.render_template(template)
            path.parent.mkdir(parents=True, exist_ok=True)
            marker = matrix.canonical[family.target_content_identifiers[0]] if family.target_content_identifiers else "unchanged-hook"
            if path.suffix == ".py":
                content = f"TARGET = {marker!r}\n"
            elif family.semantic_kind == "tracked_cli_path_set" or "/libexec/" in path.as_posix():
                content = f"#!/bin/sh\n# {marker}\nexit 0\n"
            elif family.semantic_kind == "tracked_plugin_hook_path_set" and path.name == "hooks.json":
                content = json.dumps({"hooks": {}})
            elif family.semantic_kind == "tracked_plugin_hook_path_set":
                content = f"# {marker}\n"
            elif path.suffix == ".service":
                content = f"[Unit]\nDescription={marker}\n[Service]\nExecStart=/bin/true\n"
            elif path.suffix == ".timer":
                content = f"[Unit]\nDescription={marker}\n[Timer]\nOnCalendar=hourly\n"
            elif path.suffix == ".slice":
                content = f"[Unit]\nDescription={marker}\n[Slice]\n"
            elif path.suffix == ".json":
                content = json.dumps({"identity": marker})
            elif path.suffix == ".te":
                content = f"policy_module({marker}, 1.0)\n"
            elif path.suffix == ".fc":
                content = f"/tmp/{marker} gen_context(system_u:object_r:tmp_t,s0)\n"
            elif "/sysusers.d/" in path.as_posix():
                content = f"g {marker} -\n"
            elif "/tmpfiles.d/" in path.as_posix():
                content = f"d /tmp/{marker} 0700 root root -\n"
            else:
                content = marker
            path.write_text(content, encoding="utf-8")
    cinnamon = matrix.cinnamon_surface
    cinnamon_prefix = root / matrix.render_template(cinnamon.target_path_prefix_template + "/placeholder").parent
    cinnamon_prefix.mkdir(parents=True, exist_ok=True)
    (cinnamon_prefix / cinnamon.metadata_name).write_text(
        json.dumps({"uuid": matrix.render_value(cinnamon.target_metadata_value_template)}), encoding="utf-8"
    )
    (cinnamon_prefix / cinnamon.applet_name).write_text(
        matrix.render_value(cinnamon.target_applet_value_template), encoding="utf-8"
    )
    for index in range(cinnamon.member_count - 2):
        (cinnamon_prefix / f"asset-{index:02d}.txt").write_text("target Cinnamon asset\n", encoding="utf-8")
    structured = {
        "pyproject.toml": (
            "[project]\n"
            f"name = \"{matrix.canonical['slug']}\"\n"
            "[project.scripts]\n"
            f"{matrix.canonical['slug']}-mcp = \"{matrix.canonical['python']}.server:main\"\n"
            f"{matrix.canonical['slug']}-admin = \"{matrix.canonical['python']}.admin_daemon:main\"\n"
            f"{matrix.canonical['slug']}-agent-api = \"{matrix.canonical['python']}.agent_daemon:main\"\n"
            f"{matrix.canonical['slug']}-host-agent = \"{matrix.canonical['python']}.host_agent:main\"\n"
            f"google-account-manager = \"{matrix.canonical['python']}.google_account_manager_cli:main\"\n"
        ),
        ".mcp.json": json.dumps(
            {"mcpServers": {matrix.canonical["mcp_name"]: {"command": f"/home/teladi/.local/lib/{matrix.canonical['runtime_root']}/{matrix.canonical['mcp_name']}"}}}
        ),
        ".app.json": json.dumps({"apps": {matrix.canonical["slug"]: {"id": "fixture"}}}),
        ".codex-plugin/plugin.json": json.dumps(
            {
                "name": matrix.canonical["plugin"],
                "homepage": f"https://github.com/{matrix.canonical['github_repository']}",
                "repository": f"https://github.com/{matrix.canonical['github_repository']}",
                "display": matrix.canonical["display"],
                "mcp": matrix.canonical["mcp_name"],
                "skills": "./skills/",
                "mcpServers": "./.mcp.json",
                "apps": "./.app.json",
                "hooks": "./hooks/hooks.json",
                "interface": {"displayName": matrix.canonical["display"]},
            }
        ),
    }
    for path, content in structured.items():
        destination = root / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(content, encoding="utf-8")
    for expectation in matrix.legacy_characterization:
        path = root / matrix.render_template(expectation.target_path_template)
        if path.as_posix() in {str(root / item) for item in structured}:
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        existing = path.read_text(encoding="utf-8") if path.exists() else ""
        path.write_text(
            existing + "\n" + "\n".join(matrix.render_value(value) for value in expectation.target_value_templates),
            encoding="utf-8",
        )
    for readiness in matrix.target_readiness:
        path = root / matrix.render_template(readiness.path_template)
        if path.as_posix() in {str(root / item) for item in structured}:
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        existing = path.read_text(encoding="utf-8") if path.exists() else ""
        path.write_text(existing + matrix.canonical[readiness.target_identifier], encoding="utf-8")
    contract = root / "src" / matrix.canonical["python"] / "rename_contract.v1.json"
    contract.parent.mkdir(parents=True, exist_ok=True)
    contract.write_text(files("the_hive").joinpath("rename_contract.v1.json").read_text(), encoding="utf-8")
    retirement = matrix.retirement_artifacts[0]
    target_caller = root / matrix.render_template(retirement.target_caller_path_template)
    target_caller.parent.mkdir(parents=True, exist_ok=True)
    target_caller.write_text("def load_evidence() -> None:\n    return None\n", encoding="utf-8")


def _write_d73_tree_with_contract(root: Path) -> None:
    archive = subprocess.run(
        ["git", "archive", D73_BASE], cwd=ROOT, check=True, stdout=subprocess.PIPE
    ).stdout
    with tarfile.open(fileobj=BytesIO(archive)) as bundle:
        bundle.extractall(root, filter="data")
    matrix = load_rename_matrix()
    contract = root / "src" / matrix.canonical["python"] / "rename_contract.v1.json"
    contract.parent.mkdir(parents=True, exist_ok=True)
    contract.write_text(files("the_hive").joinpath("rename_contract.v1.json").read_text(), encoding="utf-8")
    _commit_tree(root)


def test_matrix_binds_the_d74_d76_target_forms() -> None:
    matrix = load_rename_matrix()

    assert matrix.canonical["display"] == "The Hive"
    assert matrix.canonical["slug"] == "the-hive"
    assert matrix.canonical["python"] == "the_hive"
    assert matrix.canonical["environment"] == "THE_HIVE"
    assert matrix.canonical["desktop"] == "de.teladi.TheHive.ControlCenter"
    assert matrix.canonical["dbus_name"] == "org.the_hive"
    assert matrix.canonical["dbus_path"] == "/org/the_hive"
    assert matrix.canonical["c_abi_prefix"] == "the_hive_"
    assert matrix.canonical["openmetrics_namespace"] == "the_hive"
    assert matrix.canonical["compact_metrics"] == "thehive"
    assert matrix.canonical["repository"] == "the-hive"
    assert matrix.canonical["principal"] == "queen-the-hive"
    assert matrix.canonical["github_repository"] == "H234598/the-hive"
    assert matrix.canonical["checkout"] == "/home/teladi/the-hive"
    assert matrix.canonical["vault_project"] == "Projekte/The Hive"
    assert matrix.canonical["cinnamon_uuid"] == "the-hive@H234598"


def test_matrix_tampering_fails_closed() -> None:
    raw = json.loads(files("the_hive").joinpath("rename_contract.v1.json").read_text())
    missing_form = copy.deepcopy(raw)
    missing_form["legacy_forms"] = []
    changed_target = copy.deepcopy(raw)
    changed_target["canonical"]["slug"] = "unapproved-target"

    with pytest.raises(RenameContractError):
        parse_rename_matrix(missing_form)
    with pytest.raises(RenameContractError):
        parse_rename_matrix(changed_target)


def test_matrix_records_current_and_target_semantic_edges() -> None:
    matrix = load_rename_matrix()

    assert {edge.identifier for edge in matrix.legacy_characterization} == {
        "distribution",
        "python_package",
        "cli_mcp",
        "mcp_manifest",
        "app_bridge",
        "runtime_layout",
        "state_interface",
        "c_abi",
        "metrics",
        "desktop",
        "dbus_api",
        "unit",
        "plugin",
        "skill",
        "hook",
        "manpage",
        "error_surface",
    }
    for edge in matrix.legacy_characterization:
        assert edge.semantic_kind
        assert edge.caller_locators
        assert edge.legacy_value_templates
        assert edge.target_value_templates
        assert matrix.render_template(edge.path_template)
        assert matrix.render_template(edge.target_path_template)
    assert matrix.cinnamon_surface.identifier == "cinnamon_uuid"
    assert matrix.cinnamon_surface.member_count == 28
    assert matrix.render_template(matrix.cinnamon_surface.target_path_prefix_template + "/placeholder").parent.as_posix() == "cinnamon/applets/the-hive@H234598"
    assert matrix.retirement_artifacts[0].identifier == "hive_test_index"
    assert matrix.retirement_artifacts[0].disposition == "remove_from_product_tree_only"
    assert {family.identifier for family in matrix.bounded_families} == {
        "cli_entry_points", "systemd_artifacts", "hook_artifacts"
    }
    assert len(next(family for family in matrix.bounded_families if family.identifier == "cli_entry_points").legacy_path_templates) == 9
    assert len(next(family for family in matrix.bounded_families if family.identifier == "systemd_artifacts").legacy_path_templates) == 32


def test_release_gate_rejects_a_tampered_selected_tree_contract(tmp_path: Path) -> None:
    _write_target_ready_tree(tmp_path)
    contract = tmp_path / "src" / "the_hive" / "rename_contract.v1.json"
    raw = json.loads(contract.read_text(encoding="utf-8"))
    raw["canonical"]["slug"] = "unapproved-target"
    contract.write_text(json.dumps(raw), encoding="utf-8")
    _commit_tree(tmp_path)

    with pytest.raises(RenameContractError):
        RenameReleaseValidator().validate_tree(tmp_path)


def test_release_gate_rejects_invalid_structured_target_surface(tmp_path: Path) -> None:
    _write_target_ready_tree(tmp_path)
    (tmp_path / ".mcp.json").write_text("{ invalid", encoding="utf-8")
    _commit_tree(tmp_path)

    report = RenameReleaseValidator().validate_tree(tmp_path)

    assert "surface:mcp_manifest" in report.missing_target_identifiers


def test_release_gate_rejects_a_valid_manifest_with_the_target_in_the_wrong_field(tmp_path: Path) -> None:
    _write_target_ready_tree(tmp_path)
    matrix = load_rename_matrix()
    (tmp_path / ".mcp.json").write_text(
        json.dumps({"mcpServers": {"wrong": {"command": f"/home/teladi/.local/lib/{matrix.canonical['runtime_root']}/{matrix.canonical['mcp_name']}"}}}),
        encoding="utf-8",
    )
    _commit_tree(tmp_path)

    report = RenameReleaseValidator().validate_tree(tmp_path)

    assert "surface:mcp_manifest" in report.missing_target_identifiers


def test_release_gate_rejects_a_valid_plugin_with_wrong_display_or_manifest_pointer(tmp_path: Path) -> None:
    _write_target_ready_tree(tmp_path)
    plugin_path = tmp_path / ".codex-plugin" / "plugin.json"
    plugin = json.loads(plugin_path.read_text(encoding="utf-8"))
    plugin["description"] = "The Hive"
    plugin["interface"]["displayName"] = "wrong"
    plugin["hooks"] = "./wrong.json"
    plugin_path.write_text(json.dumps(plugin), encoding="utf-8")
    _commit_tree(tmp_path)

    report = RenameReleaseValidator().validate_tree(tmp_path)

    assert "surface:plugin" in report.missing_target_identifiers


def test_release_gate_rejects_the_plugin_masterjet_compatibility_alias(tmp_path: Path) -> None:
    _write_target_ready_tree(tmp_path)
    plugin_path = tmp_path / ".codex-plugin" / "plugin.json"
    plugin = json.loads(plugin_path.read_text(encoding="utf-8"))
    plugin["description"] = "masterjet REMAIN COMPATIBILITY ALIASES"
    plugin_path.write_text(json.dumps(plugin), encoding="utf-8")
    _commit_tree(tmp_path)

    report = RenameReleaseValidator().validate_tree(tmp_path)

    assert "alias:plugin_description_masterjet_alias" in report.missing_target_identifiers


def test_release_gate_preserves_a_non_alias_masterjet_component_reference(tmp_path: Path) -> None:
    _write_target_ready_tree(tmp_path)
    plugin_path = tmp_path / ".codex-plugin" / "plugin.json"
    plugin = json.loads(plugin_path.read_text(encoding="utf-8"))
    plugin["description"] = "The Masterjet component remains separately named."
    plugin_path.write_text(json.dumps(plugin), encoding="utf-8")
    _commit_tree(tmp_path)

    report = RenameReleaseValidator().validate_tree(tmp_path)

    assert "alias:plugin_description_masterjet_alias" not in report.missing_target_identifiers


def test_release_gate_rejects_a_placeholder_cli_family_member(tmp_path: Path) -> None:
    _write_target_ready_tree(tmp_path)
    matrix = load_rename_matrix()
    target = tmp_path / matrix.render_template(
        next(family for family in matrix.bounded_families if family.identifier == "cli_entry_points").target_path_templates[0]
    )
    target.write_text("target family member", encoding="utf-8")
    _commit_tree(tmp_path)

    report = RenameReleaseValidator().validate_tree(tmp_path)

    assert "family:cli_entry_points" in report.missing_target_identifiers


def test_release_gate_rejects_a_placeholder_systemd_family_member(tmp_path: Path) -> None:
    _write_target_ready_tree(tmp_path)
    matrix = load_rename_matrix()
    target = tmp_path / matrix.render_template(
        next(family for family in matrix.bounded_families if family.identifier == "systemd_artifacts").target_path_templates[0]
    )
    target.write_text(matrix.canonical["slug"], encoding="utf-8")
    _commit_tree(tmp_path)

    report = RenameReleaseValidator().validate_tree(tmp_path)

    assert "family:systemd_artifacts" in report.missing_target_identifiers


def test_release_gate_requires_removal_of_the_hive_test_index_from_the_product_tree(tmp_path: Path) -> None:
    _write_target_ready_tree(tmp_path)
    index = tmp_path / ".hive" / "test-index.v1.json"
    index.parent.mkdir(parents=True, exist_ok=True)
    index.write_text("{}", encoding="utf-8")
    _commit_tree(tmp_path)

    report = RenameReleaseValidator().validate_tree(tmp_path)

    assert "retire:hive_test_index" in report.missing_target_identifiers


def test_release_gate_rejects_a_stale_target_test_index_reader(tmp_path: Path) -> None:
    _write_target_ready_tree(tmp_path)
    matrix = load_rename_matrix()
    retirement = matrix.retirement_artifacts[0]
    target_caller = tmp_path / matrix.render_template(retirement.target_caller_path_template)
    target_caller.write_text(retirement.target_forbidden_symbol, encoding="utf-8")
    _commit_tree(tmp_path)

    report = RenameReleaseValidator().validate_tree(tmp_path)

    assert "retire:hive_test_index" in report.missing_target_identifiers


def test_characterization_rejects_a_missing_in_repo_family_caller(tmp_path: Path) -> None:
    _write_d73_tree_with_contract(tmp_path)
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(pyproject.read_text(encoding="utf-8").replace("[project.scripts]", "[tool.fixture]"), encoding="utf-8")
    subprocess.run(["git", "add", "pyproject.toml"], cwd=tmp_path, check=True)
    subprocess.run(
        ["git", "-c", "user.name=TH-R1 test", "-c", "user.email=th-r1@example.invalid", "commit", "--quiet", "-m", "missing family caller"],
        cwd=tmp_path,
        check=True,
    )

    failures = RenameReleaseValidator().characterize_legacy_surfaces(tmp_path)

    assert ("cli_entry_points", "missing_family_caller") in {
        (failure.surface_identifier, failure.reason) for failure in failures
    }


def test_current_d73_tree_is_intentionally_red_but_legacy_characterization_is_green(tmp_path: Path) -> None:
    validator = RenameReleaseValidator()

    _write_d73_tree_with_contract(tmp_path)
    assert validator.characterize_legacy_surfaces(tmp_path) == ()
    report = validator.validate_tree(tmp_path)

    assert report.legacy_findings
    assert report.missing_target_identifiers
    assert not report.ready


def test_release_gate_rejects_all_legacy_forms_in_paths_and_raw_blobs(tmp_path: Path) -> None:
    matrix = load_rename_matrix()
    for index, form in enumerate(matrix.legacy_forms.values()):
        path = tmp_path / f"item-{index}" / form.value
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(form.value.swapcase().encode("ascii"))
    _write_target_ready_tree(tmp_path)
    _commit_tree(tmp_path)

    report = RenameReleaseValidator(matrix).validate_tree(tmp_path)

    assert {finding.location for finding in report.legacy_findings} == {"content", "path"}
    assert {finding.form_identifier for finding in report.legacy_findings} == set(matrix.legacy_forms)
    assert report.missing_target_identifiers == ()
    assert not report.ready


def test_release_gate_preserves_protected_terms_when_the_cinnamon_target_is_complete(tmp_path: Path) -> None:
    matrix = load_rename_matrix()
    _write_target_ready_tree(tmp_path)
    protected = tmp_path / "protected.txt"
    protected.write_text("\n".join(matrix.protected_terms), encoding="utf-8")
    _commit_tree(tmp_path)

    report = RenameReleaseValidator(matrix).validate_tree(tmp_path)

    assert report.legacy_findings == ()
    assert report.missing_target_identifiers == ()
    assert report.ready


@pytest.mark.parametrize(("member", "content"), (("metadata.json", json.dumps({"uuid": "wrong"})), ("applet.js", 'const UUID = "wrong";')))
def test_release_gate_rejects_a_cinnamon_uuid_target_drift(tmp_path: Path, member: str, content: str) -> None:
    _write_target_ready_tree(tmp_path)
    matrix = load_rename_matrix()
    cinnamon_prefix = tmp_path / matrix.render_template(matrix.cinnamon_surface.target_path_prefix_template + "/placeholder").parent
    (cinnamon_prefix / member).write_text(content, encoding="utf-8")
    _commit_tree(tmp_path)

    report = RenameReleaseValidator(matrix).validate_tree(tmp_path)

    assert "cinnamon_uuid" in report.missing_target_identifiers


def test_release_gate_rejects_a_cinnamon_target_member_count_drift(tmp_path: Path) -> None:
    _write_target_ready_tree(tmp_path)
    matrix = load_rename_matrix()
    cinnamon_prefix = tmp_path / matrix.render_template(
        matrix.cinnamon_surface.target_path_prefix_template + "/placeholder"
    ).parent
    (cinnamon_prefix / "asset-00.txt").unlink()
    _commit_tree(tmp_path)

    report = RenameReleaseValidator(matrix).validate_tree(tmp_path)

    assert "cinnamon_uuid" in report.missing_target_identifiers


def test_release_gate_requires_a_git_top_level_and_local_tree(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _write_target_ready_tree(tmp_path)
    _commit_tree(tmp_path)

    with pytest.raises(RenameContractError):
        RenameReleaseValidator().validate_tree(tmp_path / "src")
    with pytest.raises(RenameContractError):
        RenameReleaseValidator().validate_tree(tmp_path, "--not-a-tree")
    monkeypatch.setenv("GIT_DIR", str(tmp_path / ".git"))
    with pytest.raises(RenameContractError):
        RenameReleaseValidator().validate_tree(tmp_path)
