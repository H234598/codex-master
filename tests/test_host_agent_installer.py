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
        "agent-client-key": root / "agent-client.key",
        "agent-client-cert": root / "agent-client.crt",
        "agent-master-ca": root / "agent-master-ca.crt",
        "agent-config": root / "agent-config.json",
    }
    for name, path in paths.items():
        path.write_bytes(SECRET + name.encode("ascii"))
        path.chmod(0o400 if name in {"agent-client-key", "agent-config"} else 0o444)
    return paths


def _arguments(sources: dict[str, Path], destdir: Path, *extra: str) -> list[str]:
    return [
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
    """Model packaged root-owned sources without adding an installer test flag."""

    identities = {(item.stat().st_dev, item.stat().st_ino) for item in paths}
    real_stat = module.os.stat
    real_fstat = module.os.fstat
    fchown_calls: list[tuple[int, int]] = []

    def trusted(item, *args, **kwargs):
        value = real_stat(item, *args, **kwargs)
        if (value.st_dev, value.st_ino) not in identities:
            return value
        fields = list(value)
        fields[4] = 0
        return os.stat_result(fields)

    def trusted_fd(descriptor: int):
        value = real_fstat(descriptor)
        if (value.st_dev, value.st_ino) not in identities:
            return value
        fields = list(value)
        fields[4] = 0
        return os.stat_result(fields)

    def record_fchown(_descriptor: int, uid: int, gid: int) -> None:
        fchown_calls.append((uid, gid))

    monkeypatch.setattr(module.os, "stat", trusted)
    monkeypatch.setattr(module.os, "fstat", trusted_fd)
    monkeypatch.setattr(module.os, "fchown", record_fchown)
    monkeypatch.setattr(module.os, "geteuid", lambda: 0)
    return fchown_calls


@pytest.fixture
def prepared_installer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[ModuleType, dict[str, Path], Path, list[tuple[int, int]]]:
    module = _load_installer()
    sources = _credential_sources(tmp_path / "source")
    unit = tmp_path / UNIT_NAME
    unit.write_text("[Service]\nExecStart=/usr/bin/codex-master-host-agent\n", encoding="utf-8")
    unit.chmod(0o644)
    monkeypatch.setattr(module, "UNIT_SOURCE", unit)
    destination = tmp_path / "destination"
    destination.mkdir()
    fchown_calls = _root_owned_sources(
        monkeypatch,
        module,
        sources["agent-client-key"],
        sources["agent-client-cert"],
        sources["agent-master-ca"],
        sources["agent-config"],
        unit,
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


@pytest.mark.parametrize("unsafe", ["symlink", "wrong-owner", "wrong-mode", "hardlink"])
def test_installer_rejects_unsafe_credential_sources(
    prepared_installer: tuple[ModuleType, dict[str, Path], Path, list[tuple[int, int]]],
    unsafe: str,
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
    monkeypatch.setattr(module, "UNIT_SOURCE", destination / "missing.service")

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
        "agent-config.json": (SECRET + b"agent-config", 0o400),
    }
    assert (
        destination / "etc" / "systemd" / "system" / UNIT_NAME
    ).read_text(encoding="utf-8").startswith("[Service]")
    assert all(uid_gid == (0, 0) for uid_gid in fchown_calls)
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

    def forbidden_run(*_args, **_kwargs):
        raise AssertionError("systemctl must not run without --enable")

    monkeypatch.setattr(module.subprocess, "run", forbidden_run)
    assert module.main(_arguments(sources, destination)) == 0
    captured = capsys.readouterr()
    assert SECRET.decode("ascii") not in captured.out + captured.err
    assert calls == []


def test_enable_reloads_then_enables_and_starts_only_the_host_agent_unit(
    prepared_installer: tuple[ModuleType, dict[str, Path], Path, list[tuple[int, int]]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module, sources, destination, _fchown_calls = prepared_installer
    calls: list[list[str]] = []

    def fake_run(argv: list[str], **_kwargs) -> subprocess.CompletedProcess[str]:
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0)

    monkeypatch.setattr(module.subprocess, "run", fake_run)

    assert module.main(_arguments(sources, destination, "--enable")) == 0

    assert calls == [
        ["/usr/bin/systemctl", "daemon-reload"],
        ["/usr/bin/systemctl", "enable", "--now", UNIT_NAME],
    ]
    assert all(SECRET.decode("ascii") not in " ".join(argv) for argv in calls)
    assert all("agent-api" not in " ".join(argv) for argv in calls)


def test_installer_has_no_journal_or_logging_credential_path() -> None:
    text = INSTALLER.read_text(encoding="utf-8").lower()

    assert "journal" not in text
    assert "logging" not in text
