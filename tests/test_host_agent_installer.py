from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import stat
import subprocess
import sys
from importlib.machinery import SourceFileLoader
from types import ModuleType

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
        elif name == "agent-bindings":
            path.write_bytes(b'{"schema_version":1,"hosts":[]}')
        else:
            path.write_bytes(SECRET + name.encode("ascii"))
        path.chmod(
            0o400
            if name in {"agent-server-key", "agent-bindings", "agent-client-key", "agent-config"}
            else 0o444
        )
    return paths


def _arguments(sources: dict[str, Path], destdir: Path, *extra: str) -> list[str]:
    return [
        "--agent-server-key",
        os.fspath(sources["agent-server-key"]),
        "--agent-server-cert",
        os.fspath(sources["agent-server-cert"]),
        "--agent-client-ca",
        os.fspath(sources["agent-client-ca"]),
        "--agent-bindings",
        os.fspath(sources["agent-bindings"]),
        "--agent-client-key",
        os.fspath(sources["agent-client-key"]),
        "--agent-client-cert",
        os.fspath(sources["agent-client-cert"]),
        "--agent-master-ca",
        os.fspath(sources["agent-master-ca"]),
        "--agent-config",
        os.fspath(sources["agent-config"]),
        "--destdir",
        os.fspath(destdir),
        *extra,
    ]


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
    units = {name: tmp_path / name for name in UNIT_NAMES}
    for name, unit in units.items():
        unit.write_text("[Service]\nExecStart=/usr/bin/" + name + "\n", encoding="utf-8")
        unit.chmod(0o644)
    sysusers = tmp_path / "codex-master-host-agent.sysusers"
    sysusers.write_text("g codex-master-agent-state -\n", encoding="utf-8")
    sysusers.chmod(0o644)
    tmpfiles = tmp_path / "codex-master-host-agent.tmpfiles"
    tmpfiles.write_text("d /var/lib/codex-master-agent 2770 root root -\n", encoding="utf-8")
    tmpfiles.chmod(0o644)
    monkeypatch.setattr(module, "UNIT_SOURCES", units)
    monkeypatch.setattr(module, "SYSUSERS_SOURCE", sysusers)
    monkeypatch.setattr(module, "TMPFILES_SOURCE", tmpfiles)
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
        "agent-server.key": (SECRET + b"agent-server-key", 0o400),
        "agent-server.crt": (SECRET + b"agent-server-cert", 0o444),
        "agent-client-ca.crt": (SECRET + b"agent-client-ca", 0o444),
        "agent-client.key": (SECRET + b"agent-client-key", 0o400),
        "agent-client.crt": (SECRET + b"agent-client-cert", 0o444),
        "agent-master-ca.crt": (SECRET + b"agent-master-ca", 0o444),
        "agent-config.json": (sources["agent-config"].read_bytes(), 0o400),
    }
    assert (destination / "etc" / "codex-master-admin" / "agent-bindings.json").read_bytes() == (
        b'{"schema_version":1,"hosts":[]}'
    )
    assert {
        path.name
        for path in (destination / "etc" / "systemd" / "system").iterdir()
    } == set(UNIT_NAMES)
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

    module._enable_service()

    assert calls == [
        ["/usr/bin/systemctl", "daemon-reload"],
        ["/usr/bin/systemctl", "enable", "--now", UNIT_NAME],
    ]
    assert all(SECRET.decode("ascii") not in " ".join(argv) for argv in calls)
    assert all("agent-api" not in " ".join(argv) for argv in calls)


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

    module._provision_static_layout(tmp_path)

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
        ("agent-server-key", b"replacement-key", 0o400),
        ("agent-server-cert", b"replacement-cert", 0o444),
    ):
        sources[name].chmod(0o600)
        sources[name].write_bytes(payload)
        sources[name].chmod(mode)
    real_replace = module.os.replace

    def fail_second_commit(source, target, *args, **kwargs):
        if str(source).startswith(".agent-server.crt.stage-") and target == "agent-server.crt":
            raise OSError
        return real_replace(source, target, *args, **kwargs)

    monkeypatch.setattr(module.os, "replace", fail_second_commit)

    assert module.main(arguments) == 1
    assert {path.name: path.read_bytes() for path in credentials.iterdir()} == original
    assert not list(credentials.glob(".*.stage-*"))
    assert not list(credentials.glob(".*.backup-*"))
