import ast
from dataclasses import FrozenInstanceError, fields, is_dataclass
from pathlib import Path

import pytest


try:
    from codex_master import fleet_home_broker_install as install
except ImportError:
    install = None


REPO_ROOT = Path(__file__).parents[1]
MODULE = REPO_ROOT / "src/codex_master/fleet_home_broker_install.py"
CONFIG = REPO_ROOT / "systemd/config/codex-master-home-broker.conf"
MANIFEST_SOURCE = "systemd/manifest/codex-master-home-broker-manifest-v1.json"
MANIFEST_TARGET = "/usr/lib/codex-master-home-broker/manifest-v1.json"
PAYLOAD_ROOT = "/usr/lib/codex-master-home-broker/0.10.5"
EXPECTED_DIRECTORIES = (
    ("/usr/lib/codex-master-home-broker", 0, 0, 0o555),
    ("/usr/lib/codex-master-home-broker/0.10.5", 0, 0, 0o555),
    ("/usr/lib/codex-master-home-broker/0.10.5/bin", 0, 0, 0o555),
    ("/usr/lib/codex-master-home-broker/0.10.5/python", 0, 0, 0o555),
    (
        "/usr/lib/codex-master-home-broker/0.10.5/python/codex_master",
        0,
        0,
        0o555,
    ),
    ("/etc/codex-master", 0, 0, 0o755),
)


def _api():
    assert install is not None, "fleet_home_broker_install module is missing"
    return install


def _expected_files() -> tuple[tuple[str, str, int, int, int], ...]:
    return (
        (
            "systemd/config/codex-master-home-broker.conf",
            "/etc/codex-master/home-broker.conf",
            0,
            0,
            0o400,
        ),
        (
            "bin/codex-master-home-broker",
            f"{PAYLOAD_ROOT}/bin/codex-master-home-broker",
            0,
            0,
            0o755,
        ),
        (
            "src/codex_master/__init__.py",
            f"{PAYLOAD_ROOT}/python/codex_master/__init__.py",
            0,
            0,
            0o644,
        ),
        (
            "src/codex_master/fleet_agent_launcher.py",
            f"{PAYLOAD_ROOT}/python/codex_master/fleet_agent_launcher.py",
            0,
            0,
            0o644,
        ),
        (
            "src/codex_master/fleet_home_broker.py",
            f"{PAYLOAD_ROOT}/python/codex_master/fleet_home_broker.py",
            0,
            0,
            0o644,
        ),
        (
            "src/codex_master/fleet_home_broker_client.py",
            f"{PAYLOAD_ROOT}/python/codex_master/fleet_home_broker_client.py",
            0,
            0,
            0o644,
        ),
        (
            "src/codex_master/fleet_home_broker_identity.py",
            f"{PAYLOAD_ROOT}/python/codex_master/fleet_home_broker_identity.py",
            0,
            0,
            0o644,
        ),
        (
            "src/codex_master/fleet_home_broker_linux.py",
            f"{PAYLOAD_ROOT}/python/codex_master/fleet_home_broker_linux.py",
            0,
            0,
            0o644,
        ),
        (
            "src/codex_master/fleet_home_broker_package.py",
            f"{PAYLOAD_ROOT}/python/codex_master/fleet_home_broker_package.py",
            0,
            0,
            0o644,
        ),
        (
            "src/codex_master/fleet_home_broker_protocol.py",
            f"{PAYLOAD_ROOT}/python/codex_master/fleet_home_broker_protocol.py",
            0,
            0,
            0o644,
        ),
        (
            "src/codex_master/fleet_home_broker_wal.py",
            f"{PAYLOAD_ROOT}/python/codex_master/fleet_home_broker_wal.py",
            0,
            0,
            0o644,
        ),
        (
            "systemd/manifest/codex-master-home-broker-manifest-v1.json",
            MANIFEST_TARGET,
            0,
            0,
            0o644,
        ),
        (
            "systemd/system/codex-master-agent@.service",
            "/usr/lib/systemd/system/codex-master-agent@.service",
            0,
            0,
            0o644,
        ),
        (
            "systemd/system/codex-master-home-broker.service",
            "/usr/lib/systemd/system/codex-master-home-broker.service",
            0,
            0,
            0o644,
        ),
        (
            "systemd/libexec/codex-master-agent-launcher",
            "/usr/libexec/codex-master-agent-launcher",
            0,
            0,
            0o555,
        ),
        (
            "systemd/libexec/codex-master-broker-verify",
            "/usr/libexec/codex-master-broker-verify",
            0,
            0,
            0o555,
        ),
        (
            "systemd/libexec/codex-master-home-broker",
            "/usr/libexec/codex-master-home-broker",
            0,
            0,
            0o555,
        ),
        (
            "systemd/libexec/codex_master_bootstrap.py",
            "/usr/libexec/codex_master_bootstrap.py",
            0,
            0,
            0o555,
        ),
    )


def test_public_api_is_frozen_slotted_and_minimal() -> None:
    module = _api()

    assert tuple(field.name for field in fields(module.InstallDirectory)) == (
        "path",
        "uid",
        "gid",
        "mode",
    )
    assert tuple(field.name for field in fields(module.InstallFile)) == (
        "source_path",
        "target_path",
        "uid",
        "gid",
        "mode",
    )
    assert tuple(field.name for field in fields(module.InstallPlan)) == (
        "payload_version",
        "directories",
        "files",
    )

    values = (
        module.InstallDirectory("/payload", 0, 0, 0o555),
        module.InstallFile("source", "/target", 0, 0, 0o644),
        module.InstallPlan("0.10.5", (), ()),
    )
    for value in values:
        assert is_dataclass(value)
        assert type(value).__dataclass_params__.frozen
        assert hasattr(type(value), "__slots__")
        assert not hasattr(value, "__dict__")

    with pytest.raises(FrozenInstanceError):
        values[0].mode = 0o755


def test_builder_returns_exact_sorted_duplicate_free_install_closure() -> None:
    plan = _api().build_home_broker_install_plan()

    assert plan.payload_version == "0.10.5"
    actual_directories = tuple(
        (entry.path, entry.uid, entry.gid, entry.mode) for entry in plan.directories
    )
    assert actual_directories == tuple(
        sorted(EXPECTED_DIRECTORIES, key=lambda entry: entry[0])
    )
    assert len(actual_directories) == 6
    actual = tuple(
        (
            entry.source_path,
            entry.target_path,
            entry.uid,
            entry.gid,
            entry.mode,
        )
        for entry in plan.files
    )
    assert actual == tuple(sorted(_expected_files(), key=lambda entry: entry[1]))
    assert actual == tuple(sorted(actual, key=lambda entry: entry[1]))
    assert len(actual) == 18
    assert len({entry[1] for entry in actual}) == len(actual)
    assert len(set(actual)) == len(actual)
    assert sum(entry[0] == MANIFEST_SOURCE for entry in actual) == 1
    assert sum(entry[1] == MANIFEST_TARGET for entry in actual) == 1


def test_manifest_is_reserved_but_not_payload_or_digest_closure() -> None:
    plan = _api().build_home_broker_install_plan()
    payload_files = tuple(
        entry
        for entry in plan.files
        if entry.target_path.startswith(PAYLOAD_ROOT + "/")
    )

    assert MANIFEST_TARGET not in {entry.target_path for entry in payload_files}
    assert all(not hasattr(entry, "sha256") for entry in plan.files)
    manifest = next(
        entry for entry in plan.files if entry.target_path == MANIFEST_TARGET
    )
    assert (
        manifest.source_path,
        manifest.target_path,
        manifest.uid,
        manifest.gid,
        manifest.mode,
    ) == (
        MANIFEST_SOURCE,
        MANIFEST_TARGET,
        0,
        0,
        0o644,
    )


def test_config_source_is_comment_only_and_has_exact_install_mapping() -> None:
    module = _api()
    config = CONFIG.read_text(encoding="utf-8")
    lines = [line for line in config.splitlines() if line.strip()]

    assert lines
    assert all(line.lstrip().startswith("#") for line in lines)
    assert "=" not in config
    assert not any(
        word in config.lower() for word in ("identity", "policy", "fallback")
    )
    assert any(
        entry.source_path == str(CONFIG.relative_to(CONFIG.parents[2]))
        and entry.target_path == "/etc/codex-master/home-broker.conf"
        and (entry.uid, entry.gid, entry.mode) == (0, 0, 0o400)
        for entry in module.build_home_broker_install_plan().files
    )


def test_non_manifest_sources_are_existing_e1_e2_artifacts() -> None:
    expected_sources = {
        source for source, _, _, _, _ in _expected_files() if source != MANIFEST_SOURCE
    }

    assert all((REPO_ROOT / source).is_file() for source in expected_sources)


def test_builder_is_repeatable_and_nested_values_are_immutable() -> None:
    first = _api().build_home_broker_install_plan()
    second = _api().build_home_broker_install_plan()

    assert first == second
    assert isinstance(first.directories, tuple)
    assert isinstance(first.files, tuple)
    with pytest.raises(FrozenInstanceError):
        first.files[0].target_path = "/changed"
    with pytest.raises(FrozenInstanceError):
        first.files = ()


def test_plan_module_has_no_host_io_digest_or_activation_surface() -> None:
    if not MODULE.exists():
        pytest.fail("fleet_home_broker_install module is missing")
    tree = ast.parse(MODULE.read_text(encoding="utf-8"))
    allowed_imports = {"dataclasses": {"dataclass"}}

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            pytest.fail(f"direct module import is forbidden: {ast.unparse(node)}")
        if isinstance(node, ast.ImportFrom):
            assert node.module in allowed_imports
            assert node.level == 0
            assert {alias.name for alias in node.names} <= allowed_imports[node.module]
        if isinstance(node, ast.Call):
            function = node.func
            if isinstance(function, ast.Name):
                assert function.id not in {
                    "open",
                    "exec",
                    "eval",
                    "compile",
                    "__import__",
                }
        if isinstance(node, ast.Name):
            assert node.id not in {
                "subprocess",
                "socket",
                "SCM",
                "sha256",
            }

    source = MODULE.read_text(encoding="utf-8").lower()
    assert "read_text" not in source
    assert "write_text" not in source
    assert "read_bytes" not in source
    assert "write_bytes" not in source
    assert "systemctl" not in source
    assert "semodule" not in source
    assert "setenforce" not in source
    assert "restorecon" not in source
    assert "wantedby" not in source
    assert "[install]" not in source


def test_units_have_no_activation_section() -> None:
    for path in (
        REPO_ROOT / "systemd/system/codex-master-home-broker.service",
        REPO_ROOT / "systemd/system/codex-master-agent@.service",
    ):
        source = path.read_text(encoding="utf-8")
        assert "[Install]" not in source
        assert "WantedBy=" not in source
