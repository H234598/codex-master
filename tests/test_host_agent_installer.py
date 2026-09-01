from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import stat
import subprocess
import sys
from importlib.machinery import SourceFileLoader
from types import ModuleType, SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "scripts" / "install-host-agent"
UNIT_NAME = "codex-master-host-agent.service"
UNIT_NAMES = (
    "codex-master-admin.service",
    "codex-master-agent-api.service",
    UNIT_NAME,
)
SECRET = b"credential-bytes-must-never-appear-in-output"


def _load_installer() -> ModuleType:
    name = f"host_agent_installer_{os.getpid()}"
    loader = SourceFileLoader(name, os.fspath(INSTALLER))
    specification = importlib.util.spec_from_loader(name, loader)
    assert specification is not None
    assert specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    sys.modules[name] = module
    specification.loader.exec_module(module)
    return module


def _credential_sources(root: Path) -> dict[str, Path]:
    root.mkdir()
    paths = {
        "admin-config": root / "admin-config.json",
        "admin-bearer": root / "admin-bearer",
        "admin-totp": root / "admin-totp",
        "admin-attestation": root / "admin-attestation",
        "admin-vault-key": root / "admin-vault-key",
        "admin-quota-evidence": root / "admin-quota-evidence.json",
        "agent-server-key": root / "agent-server.key",
        "agent-server-cert": root / "agent-server.crt",
        "agent-client-ca": root / "agent-client-ca.crt",
        "agent-bindings": root / "agent-bindings.json",
        "agent-client-key": root / "agent-client.key",
        "agent-client-cert": root / "agent-client.crt",
        "agent-master-ca": root / "agent-master-ca.crt",
        "agent-config": root / "agent-config.json",
    }
    for name, path in paths.items():
        if name == "agent-config":
            path.write_text(
                '{"schema_version":1,"master_url":"https://master.internal","host_ref":"worker-one","registry_generation":7,"lease_epoch":3,"capabilities_digest":"sha256:'
                + "c" * 64
                + '","state_root":"/var/lib/codex-master-host-agent","ollama_registry_path":"/var/lib/codex-master-host-agent/ollama/registry.json","max_wait_seconds":20}',
                encoding="ascii",
            )
        elif name in {"agent-bindings", "admin-quota-evidence"}:
            path.write_bytes(b'{"schema_version":1,"hosts":[]}')
        else:
            path.write_bytes(SECRET + name.encode("ascii"))
        path.chmod(
            0o400
            if name
            in {
                "admin-config",
                "admin-bearer",
                "admin-totp",
                "admin-attestation",
                "admin-vault-key",
                "admin-quota-evidence",
                "agent-server-key",
                "agent-bindings",
                "agent-client-key",
                "agent-config",
            }
            else 0o444
        )
    return paths


def _arguments(sources: dict[str, Path], destdir: Path, *extra: str) -> list[str]:
    return _role_arguments("worker", sources, destdir, *extra)


def _role_arguments(
    role: str, sources: dict[str, Path], destdir: Path, *extra: str
) -> list[str]:
    credentials = {
        "master": (
            "admin-config",
            "admin-bearer",
            "admin-totp",
            "admin-attestation",
            "admin-vault-key",
            "admin-quota-evidence",
            "agent-server-key",
            "agent-server-cert",
            "agent-client-ca",
            "agent-bindings",
            "agent-listen-address",
        ),
        "worker": (
            "agent-client-key",
            "agent-client-cert",
            "agent-master-ca",
            "agent-config",
        ),
    }[role]
    result = ["--role", role]
    for name in credentials:
        result.extend((f"--{name}", os.fspath(sources[name])))
    return [*result, "--destdir", os.fspath(destdir), *extra]


def _root_owned_sources(
    monkeypatch: pytest.MonkeyPatch, module: ModuleType, *paths: Path
) -> list[tuple[int, int]]:
    """Use the test process owner as the isolated destination-root authority."""

    del paths
    fchown_calls: list[tuple[int, int]] = []

    def record_fchown(_descriptor: int, uid: int, gid: int) -> None:
        fchown_calls.append((uid, gid))

    monkeypatch.setattr(module.os, "fchown", record_fchown)
    monkeypatch.setattr(module, "ROOT_UID", os.geteuid())
    monkeypatch.setattr(module, "ROOT_GID", os.getegid())
    return fchown_calls


@pytest.fixture
def prepared_installer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[ModuleType, dict[str, Path], Path, list[tuple[int, int]]]:
    module = _load_installer()
    sources = _credential_sources(tmp_path / "source")
    listen_address = tmp_path / "source" / "agent-listen-address"
    listen_address.write_text("10.23.4.5\n", encoding="ascii")
    listen_address.chmod(0o444)
    sources["agent-listen-address"] = listen_address
    units = {name: tmp_path / name for name in UNIT_NAMES}
    for name, unit in units.items():
        command = name.removesuffix(".service")
        unit.write_text(
            "[Service]\nExecStart=@CODEX_MASTER_BINDIR@/" + command + "\n",
            encoding="utf-8",
        )
        unit.chmod(0o644)
    sysusers = tmp_path / "codex-master-host-agent.sysusers"
    sysusers.write_text("g codex-master-agent-state -\n", encoding="utf-8")
    sysusers.chmod(0o644)
    tmpfiles = tmp_path / "codex-master-host-agent.tmpfiles"
    tmpfiles.write_text("d /var/lib/codex-master-agent 2770 root root -\n", encoding="utf-8")
    tmpfiles.chmod(0o644)
    monkeypatch.setattr(module, "UNIT_SOURCES", units)
    monkeypatch.setattr(module, "SYSUSERS_SOURCE", sysusers, raising=False)
    monkeypatch.setattr(module, "TMPFILES_SOURCE", tmpfiles, raising=False)
    monkeypatch.setattr(
        module,
        "SYSUSERS_SOURCES",
        {"master": sysusers, "worker": sysusers},
        raising=False,
    )
    monkeypatch.setattr(
        module,
        "TMPFILES_SOURCES",
        {"master": tmpfiles, "worker": tmpfiles},
        raising=False,
    )
    destination = tmp_path / "destination"
    destination.mkdir()
    fchown_calls = _root_owned_sources(
        monkeypatch,
        module,
        *sources.values(),
        *units.values(),
        sysusers,
        tmpfiles,
    )
    return module, sources, destination, fchown_calls


def test_worker_role_never_accepts_or_installs_master_credentials(
    prepared_installer: tuple[ModuleType, dict[str, Path], Path, list[tuple[int, int]]],
) -> None:
    module, sources, destination, _fchown_calls = prepared_installer

    assert module.main(_role_arguments("worker", sources, destination)) == 0

    credentials = destination / "etc" / "codex-master"
    assert {path.name for path in credentials.iterdir()} == {
        "agent-client.key",
        "agent-client.crt",
        "agent-master-ca.crt",
        "agent-config.json",
    }
    assert not (destination / "etc" / "codex-master-admin").exists()
    assert {
        path.name for path in (destination / "etc" / "systemd" / "system").iterdir()
    } == {"codex-master-host-agent.service"}


def test_master_role_never_accepts_or_installs_worker_credentials(
    prepared_installer: tuple[ModuleType, dict[str, Path], Path, list[tuple[int, int]]],
) -> None:
    module, sources, destination, _fchown_calls = prepared_installer

    assert module.main(_role_arguments("master", sources, destination)) == 0

    credentials = destination / "etc" / "codex-master"
    assert {path.name for path in credentials.iterdir()} == {
        "agent-server.key",
        "agent-server.crt",
        "agent-client-ca.crt",
        "agent-listen-address",
    }
    assert {
        path.name
        for path in (destination / "etc" / "codex-master-admin").iterdir()
    } == {
        "admin-config.json",
        "admin-bearer",
        "admin-totp",
        "admin-attestation",
        "admin-vault-key",
        "admin-quota-evidence.json",
        "agent-bindings.json",
    }
    assert {
        path.name for path in (destination / "etc" / "systemd" / "system").iterdir()
    } == {
        "codex-master-admin.service",
        "codex-master-agent-api.service",
    }


@pytest.mark.parametrize(
    ("first_role", "second_role"),
    (("worker", "master"), ("master", "worker")),
)
def test_in_place_role_upgrade_removes_foreign_installer_artifacts(
    prepared_installer: tuple[ModuleType, dict[str, Path], Path, list[tuple[int, int]]],
    first_role: str,
    second_role: str,
) -> None:
    module, sources, destination, _fchown_calls = prepared_installer

    assert module.main(_role_arguments(first_role, sources, destination)) == 0
    assert module.main(_role_arguments(second_role, sources, destination)) == 0

    credentials = destination / "etc" / "codex-master"
    expected_credentials = {
        "master": {
            "agent-server.key",
            "agent-server.crt",
            "agent-client-ca.crt",
            "agent-listen-address",
        },
        "worker": {
            "agent-client.key",
            "agent-client.crt",
            "agent-master-ca.crt",
            "agent-config.json",
        },
    }[second_role]
    expected_units = {
        "master": {
            "codex-master-admin.service",
            "codex-master-agent-api.service",
        },
        "worker": {"codex-master-host-agent.service"},
    }[second_role]
    expected_layout = {
        "master": "codex-master-agent-api.conf",
        "worker": "codex-master-host-agent.conf",
    }[second_role]
    assert {path.name for path in credentials.iterdir()} == expected_credentials
    assert {
        path.name for path in (destination / "etc/systemd/system").iterdir()
    } == expected_units
    assert {
        path.name for path in (destination / "usr/lib/sysusers.d").iterdir()
    } == {expected_layout}
    assert {
        path.name for path in (destination / "usr/lib/tmpfiles.d").iterdir()
    } == {expected_layout}
    admin_credentials = destination / "etc/codex-master-admin"
    if second_role == "master":
        assert len(list(admin_credentials.iterdir())) == 7
    else:
        assert not admin_credentials.exists() or list(admin_credentials.iterdir()) == []


@pytest.mark.parametrize(
    ("role", "foreign"),
    (("worker", "agent-server-key"), ("master", "agent-client-key")),
)
def test_roles_reject_foreign_credentials_before_mutation(
    prepared_installer: tuple[ModuleType, dict[str, Path], Path, list[tuple[int, int]]],
    role: str,
    foreign: str,
) -> None:
    module, sources, destination, _fchown_calls = prepared_installer
    arguments = _role_arguments(role, sources, destination)
    arguments.extend((f"--{foreign}", os.fspath(sources[foreign])))

    assert module.main(arguments) == 1
    assert list(destination.iterdir()) == []


def test_installer_rejects_relative_credential_paths_without_disclosing_content(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    module = _load_installer()

    assert module.main(["--agent-client-key", "relative.key"]) == 1

    captured = capsys.readouterr()
    assert SECRET.decode("ascii") not in captured.out + captured.err
    assert not (tmp_path / "etc").exists()


def test_packaged_installer_finds_data_beside_its_install_prefix(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load_installer()
    executable = tmp_path / "libexec" / "codex-master" / "install-host-agent"
    data = tmp_path / "lib" / "codex-master"
    (data / "systemd").mkdir(parents=True)
    monkeypatch.setattr(module, "__file__", os.fspath(executable))
    monkeypatch.setattr(module.sysconfig, "get_path", lambda _name: "/missing")

    assert module._packaged_source_directory() == data


def test_installed_scripts_directory_follows_packaged_installer_prefix(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_installer()
    monkeypatch.setattr(
        module,
        "__file__",
        "/opt/codex-master-venv/libexec/codex-master/install-host-agent",
    )

    assert module._installed_scripts_directory() == Path("/opt/codex-master-venv/bin")


def test_installed_scripts_directory_rejects_systemd_dollar_expansion(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_installer()
    monkeypatch.setattr(
        module,
        "__file__",
        "/opt/codex$master/libexec/codex-master/install-host-agent",
    )

    with pytest.raises(module.InstallerError):
        module._installed_scripts_directory()


def test_installer_renders_unit_entrypoint_from_its_install_prefix(
    prepared_installer: tuple[ModuleType, dict[str, Path], Path, list[tuple[int, int]]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module, sources, destination, _fchown_calls = prepared_installer
    monkeypatch.setattr(
        module,
        "__file__",
        "/opt/codex-master-venv/libexec/codex-master/install-host-agent",
    )

    assert module.main(_arguments(sources, destination)) == 0

    installed = destination / "etc/systemd/system/codex-master-host-agent.service"
    assert installed.read_text(encoding="utf-8") == (
        "[Service]\n"
        "ExecStart=/opt/codex-master-venv/bin/codex-master-host-agent\n"
    )


@pytest.mark.parametrize("unsafe", ["symlink", "wrong-owner", "wrong-mode", "hardlink"])
def test_installer_rejects_unsafe_credential_sources(
    prepared_installer: tuple[ModuleType, dict[str, Path], Path, list[tuple[int, int]]],
    unsafe: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module, sources, destination, _fchown_calls = prepared_installer
    key = sources["agent-client-key"]
    if unsafe == "symlink":
        replacement = key.with_name("replacement.key")
        replacement.write_bytes(SECRET)
        replacement.chmod(0o400)
        key.unlink()
        key.symlink_to(replacement)
    elif unsafe == "wrong-owner":
        replacement = key.with_name("foreign.key")
        replacement.write_bytes(SECRET)
        replacement.chmod(0o400)
        sources["agent-client-key"] = replacement
        monkeypatch.setattr(module, "ROOT_UID", 0)
        monkeypatch.setattr(module.os, "geteuid", lambda: 0)
    elif unsafe == "wrong-mode":
        key.chmod(0o600)
    else:
        os.link(key, key.with_name("linked.key"))

    assert module.main(_arguments(sources, destination)) == 1
    assert not (destination / "etc").exists()


def test_installer_requires_a_trusted_existing_unit(
    prepared_installer: tuple[ModuleType, dict[str, Path], Path, list[tuple[int, int]]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module, sources, destination, _fchown_calls = prepared_installer
    missing = dict(module.UNIT_SOURCES)
    missing[UNIT_NAME] = destination / "missing.service"
    monkeypatch.setattr(module, "UNIT_SOURCES", missing)

    assert module.main(_arguments(sources, destination)) == 1
    assert not (destination / "etc").exists()


def test_dry_run_is_fully_validated_but_does_not_mutate(
    prepared_installer: tuple[ModuleType, dict[str, Path], Path, list[tuple[int, int]]],
) -> None:
    module, sources, destination, fchown_calls = prepared_installer

    assert module.main(_arguments(sources, destination, "--dry-run")) == 0

    assert list(destination.iterdir()) == []
    assert fchown_calls == []


def test_install_is_atomic_idempotent_and_uses_exact_modes(
    prepared_installer: tuple[ModuleType, dict[str, Path], Path, list[tuple[int, int]]],
) -> None:
    module, sources, destination, fchown_calls = prepared_installer
    arguments = _arguments(sources, destination)

    assert module.main(arguments) == 0
    credentials = destination / "etc" / "codex-master"
    installed = {
        path.name: (path.read_bytes(), stat.S_IMODE(path.stat().st_mode))
        for path in credentials.iterdir()
    }
    assert installed == {
        "agent-client.key": (SECRET + b"agent-client-key", 0o400),
        "agent-client.crt": (SECRET + b"agent-client-cert", 0o444),
        "agent-master-ca.crt": (SECRET + b"agent-master-ca", 0o444),
        "agent-config.json": (sources["agent-config"].read_bytes(), 0o400),
    }
    assert not (destination / "etc" / "codex-master-admin").exists()
    assert {
        path.name
        for path in (destination / "etc" / "systemd" / "system").iterdir()
    } == {UNIT_NAME}
    assert (destination / "usr" / "lib" / "sysusers.d" / "codex-master-host-agent.conf").is_file()
    assert (destination / "usr" / "lib" / "tmpfiles.d" / "codex-master-host-agent.conf").is_file()
    assert all(uid_gid == (os.geteuid(), os.getegid()) for uid_gid in fchown_calls)
    assert not list(credentials.glob(".*.tmp"))

    assert module.main(arguments) == 0
    assert {
        path.name: (path.read_bytes(), stat.S_IMODE(path.stat().st_mode))
        for path in credentials.iterdir()
    } == installed


def test_systemctl_is_never_called_without_enable_and_never_receives_credential_bytes(
    prepared_installer: tuple[ModuleType, dict[str, Path], Path, list[tuple[int, int]]],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    module, sources, destination, _fchown_calls = prepared_installer
    calls: list[list[str]] = []

    def record_run(argv: list[str], **_kwargs) -> subprocess.CompletedProcess[str]:
        calls.append(argv)
        assert argv[0] != "/usr/bin/systemctl"
        return subprocess.CompletedProcess(argv, 0)

    monkeypatch.setattr(module.subprocess, "run", record_run)
    assert module.main(_arguments(sources, destination)) == 0
    captured = capsys.readouterr()
    assert SECRET.decode("ascii") not in captured.out + captured.err
    assert calls == []


def test_enable_reloads_then_enables_and_starts_only_the_host_agent_unit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_installer()
    calls: list[list[str]] = []

    def fake_run(argv: list[str], **_kwargs) -> subprocess.CompletedProcess[str]:
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0)

    monkeypatch.setattr(module.subprocess, "run", fake_run)

    module._enable_service("worker")

    assert calls == [
        ["/usr/bin/systemctl", "daemon-reload"],
        ["/usr/bin/systemctl", "enable", UNIT_NAME],
        ["/usr/bin/systemctl", "restart", UNIT_NAME],
    ]
    assert all(SECRET.decode("ascii") not in " ".join(argv) for argv in calls)
    assert all("agent-api" not in " ".join(argv) for argv in calls)


def test_master_enable_starts_admin_and_agent_api_units(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_installer()
    calls: list[list[str]] = []
    monkeypatch.setattr(
        module.subprocess,
        "run",
        lambda argv, **_kwargs: calls.append(argv)
        or subprocess.CompletedProcess(argv, 0),
    )

    module._enable_service("master")

    assert calls == [
        ["/usr/bin/systemctl", "daemon-reload"],
        [
            "/usr/bin/systemctl",
            "enable",
            "codex-master-admin.service",
            "codex-master-agent-api.service",
        ],
        [
            "/usr/bin/systemctl",
            "restart",
            "codex-master-admin.service",
            "codex-master-agent-api.service",
        ],
    ]


def test_role_switch_stops_and_disables_only_foreign_units(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_installer()
    calls: list[list[str]] = []
    monkeypatch.setattr(
        module.subprocess,
        "run",
        lambda argv, **_kwargs: calls.append(argv)
        or subprocess.CompletedProcess(argv, 0),
    )

    module._disable_foreign_services("master")

    assert calls == [
        [
            "/usr/bin/systemctl",
            "disable",
            "--now",
            "codex-master-host-agent.service",
        ],
        ["/usr/bin/systemctl", "daemon-reload"],
    ]


def test_live_role_switch_failure_restores_exact_foreign_service_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_installer()
    states = (
        module._ServiceState("foreign-enabled.service", True, False),
        module._ServiceState("foreign-active.service", False, True),
    )
    events: list[object] = []
    monkeypatch.setattr(
        module,
        "_capture_service_states",
        lambda units: events.append(("capture", units)) or states,
    )
    monkeypatch.setattr(
        module,
        "_disable_foreign_services",
        lambda _role: events.append("disable"),
    )
    monkeypatch.setattr(
        module,
        "_commit_staged",
        lambda *_args, after_commit: events.append("commit") or after_commit(),
    )
    monkeypatch.setattr(
        module,
        "_restore_service_states",
        lambda role, value: events.append(("restore", role, value)),
    )
    provisioning = object()
    monkeypatch.setattr(
        module,
        "_capture_provisioning_state",
        lambda role: events.append(("capture-provisioning", role)) or provisioning,
    )
    monkeypatch.setattr(
        module,
        "_restore_provisioning_state",
        lambda role, value: events.append(("restore-provisioning", role, value)),
    )

    with pytest.raises(OSError):
        module._commit_role_files(
            (),
            (),
            (),
            role="master",
            live=True,
            existing_units=("codex-master-host-agent.service",),
            after_commit=lambda: events.append("finalize")
            or (_ for _ in ()).throw(OSError()),
        )

    assert events == [
        ("capture", ("codex-master-host-agent.service",)),
        ("capture-provisioning", "master"),
        "disable",
        "commit",
        "finalize",
        ("restore", "master", states),
        ("restore-provisioning", "master", provisioning),
    ]


def test_live_role_rollback_attempts_provisioning_after_service_restore_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_installer()
    events: list[str] = []
    provisioning = object()
    monkeypatch.setattr(module, "_capture_service_states", lambda _units: ())
    monkeypatch.setattr(
        module,
        "_capture_provisioning_state",
        lambda _role: provisioning,
    )
    monkeypatch.setattr(
        module,
        "_commit_staged",
        lambda *_args, after_commit: after_commit(),
    )
    monkeypatch.setattr(
        module,
        "_restore_service_states",
        lambda _role, _states: events.append("services")
        or (_ for _ in ()).throw(OSError()),
    )
    monkeypatch.setattr(
        module,
        "_restore_provisioning_state",
        lambda _role, value: events.append("provisioning")
        if value is provisioning
        else None,
    )

    with pytest.raises(module.InstallerError):
        module._commit_role_files(
            (),
            (),
            (),
            role="worker",
            live=True,
            existing_units=(),
            after_commit=lambda: (_ for _ in ()).throw(OSError()),
        )

    assert events == ["services", "provisioning"]


def test_provisioning_rollback_removes_only_new_role_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_installer()
    removed_directories: list[Path] = []
    commands: list[list[str]] = []
    existing_users = {"codex-master-admin", "codex-master-agent-api"}
    existing_groups = {
        "codex-master-admin",
        "codex-master-agent-api",
        "codex-master-agent-state",
    }

    def user(name: str) -> object:
        if name not in existing_users:
            raise KeyError(name)
        return object()

    def group(name: str) -> object:
        if name not in existing_groups:
            raise KeyError(name)
        return SimpleNamespace(gr_mem=[])

    monkeypatch.setattr(module.pwd, "getpwnam", user)
    monkeypatch.setattr(module.grp, "getgrnam", group)
    def remove_tree(path: Path) -> None:
        removed_directories.append(Path(path))

    remove_tree.avoids_symlink_attacks = True  # type: ignore[attr-defined]
    monkeypatch.setattr(module.shutil, "rmtree", remove_tree)

    def run(argv: list[str], **_kwargs) -> subprocess.CompletedProcess[str]:
        commands.append(argv)
        if argv[0] == "/usr/sbin/userdel":
            existing_users.remove(argv[1])
        else:
            existing_groups.remove(argv[1])
        return subprocess.CompletedProcess(argv, 0)

    monkeypatch.setattr(module.subprocess, "run", run)
    state = module._ProvisioningState(
        users=frozenset({"codex-master-admin"}),
        groups=frozenset({"codex-master-admin", "codex-master-agent-state"}),
        group_memberships=(
            ("codex-master-admin", frozenset()),
            ("codex-master-agent-state", frozenset()),
        ),
        directories=(),
    )

    module._restore_provisioning_state("master", state)

    assert removed_directories == [
        Path("/var/lib/codex-master-agent"),
        Path("/var/lib/codex-master-admin"),
    ]
    assert commands == [
        ["/usr/sbin/userdel", "codex-master-agent-api"],
        ["/usr/sbin/groupdel", "codex-master-agent-api"],
    ]


def test_provisioning_snapshot_records_existing_principals_and_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load_installer()
    existing = tmp_path / "existing"
    existing.mkdir()
    missing = tmp_path / "missing"
    monkeypatch.setitem(
        module.ROLE_USERS,
        "worker",
        ("existing-user", "missing-user"),
    )
    monkeypatch.setitem(
        module.ROLE_GROUPS,
        "worker",
        ("existing-group", "missing-group"),
    )
    monkeypatch.setitem(module.ROLE_STATE_DIRECTORIES, "worker", (existing, missing))
    monkeypatch.setattr(
        module.pwd,
        "getpwnam",
        lambda name: object()
        if name == "existing-user"
        else (_ for _ in ()).throw(KeyError(name)),
    )
    monkeypatch.setattr(
        module.grp,
        "getgrnam",
        lambda name: SimpleNamespace(gr_mem=["member"])
        if name == "existing-group"
        else (_ for _ in ()).throw(KeyError(name)),
    )

    existing_stat = existing.lstat()

    assert module._capture_provisioning_state("worker") == module._ProvisioningState(
        users=frozenset({"existing-user"}),
        groups=frozenset({"existing-group"}),
        group_memberships=(("existing-group", frozenset({"member"})),),
        directories=(
            module._DirectoryState(
                existing,
                existing_stat.st_dev,
                existing_stat.st_ino,
                existing_stat.st_uid,
                existing_stat.st_gid,
                stat.S_IMODE(existing_stat.st_mode),
            ),
        ),
    )


def test_provisioning_rollback_restores_directory_metadata_and_group_membership(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_installer()
    path = Path("/var/lib/codex-master-agent")
    directory = module._DirectoryState(path, 11, 22, 33, 44, 0o2750)
    calls: list[object] = []
    monkeypatch.setitem(module.ROLE_USERS, "master", ())
    monkeypatch.setitem(module.ROLE_GROUPS, "master", ("state-group",))
    monkeypatch.setitem(module.ROLE_STATE_DIRECTORIES, "master", (path,))
    monkeypatch.setattr(module.os, "open", lambda *args, **kwargs: 91)
    monkeypatch.setattr(
        module.os,
        "fstat",
        lambda _descriptor: SimpleNamespace(st_dev=11, st_ino=22),
    )
    monkeypatch.setattr(
        module.os,
        "fchown",
        lambda descriptor, uid, gid: calls.append(("chown", descriptor, uid, gid)),
    )
    monkeypatch.setattr(
        module.os,
        "fchmod",
        lambda descriptor, mode: calls.append(("chmod", descriptor, mode)),
    )
    monkeypatch.setattr(module.os, "fsync", lambda descriptor: calls.append(("fsync", descriptor)))
    monkeypatch.setattr(module.os, "close", lambda descriptor: calls.append(("close", descriptor)))
    memberships = {"state-group": ["kept", "added"]}
    monkeypatch.setattr(
        module.grp,
        "getgrnam",
        lambda name: SimpleNamespace(gr_mem=memberships[name]),
    )

    def run(argv: list[str], **_kwargs) -> subprocess.CompletedProcess[str]:
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0)

    monkeypatch.setattr(module.subprocess, "run", run)
    state = module._ProvisioningState(
        users=frozenset(),
        groups=frozenset({"state-group"}),
        group_memberships=(("state-group", frozenset({"kept", "removed"})),),
        directories=(directory,),
    )

    module._restore_provisioning_state("master", state)

    assert calls == [
        ("chown", 91, 33, 44),
        ("chmod", 91, 0o2750),
        ("fsync", 91),
        ("close", 91),
        ["/usr/sbin/gpasswd", "--delete", "added", "state-group"],
        ["/usr/sbin/gpasswd", "--add", "removed", "state-group"],
    ]


def test_post_commit_failure_restores_previous_complete_file_generation(
    prepared_installer: tuple[ModuleType, dict[str, Path], Path, list[tuple[int, int]]],
) -> None:
    module, sources, destination, _fchown_calls = prepared_installer
    assert module.main(_role_arguments("master", sources, destination)) == 0
    original = {
        path.relative_to(destination): (path.read_bytes(), stat.S_IMODE(path.stat().st_mode))
        for path in destination.rglob("*")
        if path.is_file()
    }
    arguments = module._parse_arguments(_role_arguments("worker", sources, destination))
    source_records = module._sources(arguments)
    directories: dict[str, int] = {}
    try:
        directories = module._destination_directories(
            arguments.destdir,
            frozenset(source.directory for source in source_records),
            arguments.role,
        )
        removals = [
            removal
            for removal in module._foreign_removals(arguments.role, directories)
            if module._assert_existing_destination(
                removal.parent, removal.name, removal.mode
            )
        ]
        staged = [
            module._stage(source, directories[source.directory])
            for source in source_records
        ]
        with pytest.raises(OSError):
            module._commit_staged(
                staged,
                [source.mode for source in source_records],
                removals,
                after_commit=lambda: (_ for _ in ()).throw(OSError()),
            )
    finally:
        module._close_directories(directories)
        for source in source_records:
            os.close(source.descriptor)

    assert {
        path.relative_to(destination): (path.read_bytes(), stat.S_IMODE(path.stat().st_mode))
        for path in destination.rglob("*")
        if path.is_file()
    } == original


def test_service_state_restore_removes_new_role_and_preserves_previous_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_installer()
    calls: list[list[str]] = []

    def fake_run(argv: list[str], **_kwargs) -> subprocess.CompletedProcess[str]:
        calls.append(argv)
        returncode = 0 if argv[1:] in (
            ["is-enabled", "--quiet", "codex-master-admin.service"],
            ["is-active", "--quiet", "codex-master-agent-api.service"],
        ) else 1 if argv[1] == "is-enabled" else 3
        return subprocess.CompletedProcess(argv, returncode)

    monkeypatch.setattr(module.subprocess, "run", fake_run)

    states = module._capture_service_states(
        ("codex-master-admin.service", "codex-master-agent-api.service")
    )
    module._restore_service_states("worker", states)

    assert states == (
        module._ServiceState("codex-master-admin.service", True, False),
        module._ServiceState("codex-master-agent-api.service", False, True),
    )
    assert calls[-8:] == [
        ["/usr/bin/systemctl", "daemon-reload"],
        [
            "/usr/bin/systemctl",
            "disable",
            "--now",
            "codex-master-host-agent.service",
        ],
        [
            "/usr/bin/systemctl",
            "is-enabled",
            "--quiet",
            "codex-master-host-agent.service",
        ],
        [
            "/usr/bin/systemctl",
            "is-active",
            "--quiet",
            "codex-master-host-agent.service",
        ],
        ["/usr/bin/systemctl", "enable", "codex-master-admin.service"],
        ["/usr/bin/systemctl", "stop", "codex-master-admin.service"],
        ["/usr/bin/systemctl", "disable", "codex-master-agent-api.service"],
        ["/usr/bin/systemctl", "start", "codex-master-agent-api.service"],
    ]


def test_static_layout_provisioner_is_scoped_to_its_destination_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load_installer()
    calls: list[list[str]] = []
    monkeypatch.setattr(
        module.subprocess,
        "run",
        lambda argv, **_kwargs: calls.append(argv)
        or subprocess.CompletedProcess(argv, 0),
    )

    module._provision_static_layout(tmp_path, "worker")

    assert calls == [
        [
            "/usr/bin/systemd-sysusers",
            f"--root={tmp_path}",
            f"{tmp_path}/usr/lib/sysusers.d/codex-master-host-agent.conf",
        ],
        [
            "/usr/bin/systemd-tmpfiles",
            f"--root={tmp_path}",
            "--create",
            f"{tmp_path}/usr/lib/tmpfiles.d/codex-master-host-agent.conf",
        ],
    ]


def test_live_role_finalize_provisions_layout_before_optional_enable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_installer()
    events: list[object] = []
    monkeypatch.setattr(
        module,
        "_provision_static_layout",
        lambda destination, role: events.append(("provision", destination, role)),
    )
    monkeypatch.setattr(
        module,
        "_enable_service",
        lambda role: events.append(("enable", role)),
    )

    module._finalize_live_role("worker", True)

    assert events == [
        ("provision", Path("/"), "worker"),
        ("enable", "worker"),
    ]


def test_installer_has_no_journal_or_logging_credential_path() -> None:
    text = INSTALLER.read_text(encoding="utf-8").lower()

    assert "journal" not in text
    assert "logging" not in text


def test_enable_rejects_a_staged_destdir_before_any_mutation_or_systemctl(
    prepared_installer: tuple[ModuleType, dict[str, Path], Path, list[tuple[int, int]]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A staging root must never enable a unit on the running host."""

    module, sources, destination, _fchown_calls = prepared_installer
    calls: list[list[str]] = []
    monkeypatch.setattr(
        module.subprocess,
        "run",
        lambda argv, **_kwargs: calls.append(argv) or subprocess.CompletedProcess(argv, 0),
    )

    assert module.main(_arguments(sources, destination, "--enable")) == 1

    assert list(destination.iterdir()) == []
    assert calls == []


def test_installer_rejects_an_existing_target_directory_with_the_wrong_mode(
    prepared_installer: tuple[ModuleType, dict[str, Path], Path, list[tuple[int, int]]],
) -> None:
    """Do not silently place root credentials below an inherited loose directory."""

    module, sources, destination, _fchown_calls = prepared_installer
    (destination / "etc").mkdir(mode=0o700)

    assert module.main(_arguments(sources, destination)) == 1
    assert not (destination / "etc" / "codex-master").exists()


def test_copy_failure_leaves_no_partial_credential_set(
    prepared_installer: tuple[ModuleType, dict[str, Path], Path, list[tuple[int, int]]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """All credentials are staged before the visible generation is replaced."""

    module, sources, destination, _fchown_calls = prepared_installer
    original_copy = module._copy_atomically
    calls = 0

    def fail_third_copy(*args: object) -> None:
        nonlocal calls
        calls += 1
        if calls == 3:
            raise OSError
        original_copy(*args)

    monkeypatch.setattr(module, "_copy_atomically", fail_third_copy)

    assert module.main(_arguments(sources, destination)) == 1
    credentials = destination / "etc" / "codex-master"
    assert not credentials.exists() or list(credentials.iterdir()) == []


def test_commit_failure_restores_the_previous_complete_generation(
    prepared_installer: tuple[ModuleType, dict[str, Path], Path, list[tuple[int, int]]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module, sources, destination, _fchown_calls = prepared_installer
    arguments = _arguments(sources, destination)
    assert module.main(arguments) == 0
    credentials = destination / "etc" / "codex-master"
    original = {path.name: path.read_bytes() for path in credentials.iterdir()}
    for name, payload, mode in (
        ("agent-client-key", b"replacement-key", 0o400),
        ("agent-client-cert", b"replacement-cert", 0o444),
    ):
        sources[name].chmod(0o600)
        sources[name].write_bytes(payload)
        sources[name].chmod(mode)
    real_replace = module.os.replace

    def fail_second_commit(source, target, *args, **kwargs):
        if str(source).startswith(".agent-client.crt.stage-") and target == "agent-client.crt":
            raise OSError
        return real_replace(source, target, *args, **kwargs)

    monkeypatch.setattr(module.os, "replace", fail_second_commit)

    assert module.main(arguments) == 1
    assert {path.name: path.read_bytes() for path in credentials.iterdir()} == original
    assert not list(credentials.glob(".*.stage-*"))
    assert not list(credentials.glob(".*.backup-*"))


def test_role_switch_commit_failure_restores_foreign_artifacts(
    prepared_installer: tuple[ModuleType, dict[str, Path], Path, list[tuple[int, int]]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module, sources, destination, _fchown_calls = prepared_installer
    assert module.main(_role_arguments("master", sources, destination)) == 0
    original = {
        path.relative_to(destination): (path.read_bytes(), stat.S_IMODE(path.stat().st_mode))
        for path in destination.rglob("*")
        if path.is_file()
    }
    real_replace = module.os.replace

    def fail_first_worker_commit(source, target, *args, **kwargs):
        if str(source).startswith(".agent-client.key.stage-"):
            raise OSError
        return real_replace(source, target, *args, **kwargs)

    monkeypatch.setattr(module.os, "replace", fail_first_worker_commit)

    assert module.main(_role_arguments("worker", sources, destination)) == 1
    assert {
        path.relative_to(destination): (path.read_bytes(), stat.S_IMODE(path.stat().st_mode))
        for path in destination.rglob("*")
        if path.is_file()
    } == original
