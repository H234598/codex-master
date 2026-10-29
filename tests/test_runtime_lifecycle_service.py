from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import runpy
import shutil
import socket
import subprocess
import sys
import fcntl
import multiprocessing
import stat
import tempfile
import time
from collections.abc import Mapping, Sequence
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "the-hive-runtime-service"
sys.path.insert(0, str(ROOT / "src"))

from the_hive import runtime_lifecycle, usage_snapshot  # noqa: E402
from the_hive.hook_session_pin_store import HookSessionPinStoreV1  # noqa: E402


_CANARY_GENERATION = "a" * 40
_CANARY_DIGEST = "sha256:" + "b" * 64
_LIVE_CANARY_FIXTURE = (
    ROOT / "tests" / "fixtures" / "runtime_lifecycle" / "live-canary-v1.json"
)
_CANARY_STAGE_CODES = (
    "command_runtime_directory_unavailable",
    "command_spawn_helper_unavailable",
    "command_cgroup_preflight_unavailable",
    "command_manager_preflight_unavailable",
    "command_native_spawn_unavailable",
    "command_cgroup_bind_unavailable",
)
_CUTOVER_TEST_PROFILE = b"synthetic stage profile for lifecycle mechanics only\n"
_TEST_CODEX_CLIENT_ENV = "THE_HIVE_TEST_CODEX_CLIENT"
_TEST_CODEX_CLIENT_SHA256 = (
    "9a820c17865fa825d04db416818679a9d63bd72e50835c396f496e5684626c9c"
)


def _replace_file_with_live_inode(
    path: Path, content: bytes, mode: int
) -> os.stat_result:
    """Atomically replace a file with a distinct inode while both exist."""

    original = path.lstat()
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.replacement-", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, mode)
        remaining = memoryview(content)
        while remaining:
            written = os.write(descriptor, remaining)
            if written <= 0:
                raise OSError("short write for replacement fixture")
            remaining = remaining[written:]
        os.fsync(descriptor)
        prepared = os.fstat(descriptor)
        if (prepared.st_dev, prepared.st_ino) == (original.st_dev, original.st_ino):
            raise AssertionError("replacement must be a distinct live inode")
        os.close(descriptor)
        descriptor = -1
        os.replace(temporary, path)
        replacement = path.lstat()
        assert (replacement.st_dev, replacement.st_ino) != (
            original.st_dev,
            original.st_ino,
        )
        assert stat.S_IMODE(replacement.st_mode) == mode
        assert replacement.st_uid == original.st_uid
        assert replacement.st_gid == original.st_gid
        assert replacement.st_nlink == 1
        assert path.read_bytes() == content
        return replacement
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _bind_test_codex_client(monkeypatch: pytest.MonkeyPatch) -> str | None:
    """Bind CI's verified official client bytes to the real metadata producer."""

    supplied = os.environ.get(_TEST_CODEX_CLIENT_ENV)
    if supplied is None:
        return None
    client = Path(supplied)
    before = client.lstat()
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_uid != os.geteuid()
        or before.st_nlink != 1
        or stat.S_IMODE(before.st_mode) != 0o755
    ):
        pytest.fail("pinned Codex client input has invalid physical metadata")

    def current_digest() -> str | None:
        descriptor = -1
        try:
            descriptor = os.open(
                client,
                os.O_RDONLY
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0),
            )
            opened = os.fstat(descriptor)
            current = client.lstat()
            if (
                not stat.S_ISREG(opened.st_mode)
                or opened.st_uid != os.geteuid()
                or opened.st_nlink != 1
                or stat.S_IMODE(opened.st_mode) != 0o755
                or (opened.st_dev, opened.st_ino, opened.st_size)
                != (before.st_dev, before.st_ino, before.st_size)
                or (current.st_dev, current.st_ino) != (before.st_dev, before.st_ino)
                or opened.st_size <= 0
            ):
                return None
            digest = hashlib.sha256()
            offset = 0
            while offset < opened.st_size:
                chunk = os.pread(
                    descriptor, min(1024 * 1024, opened.st_size - offset), offset
                )
                if not chunk:
                    return None
                digest.update(chunk)
                offset += len(chunk)
            if os.fstat(descriptor).st_size != opened.st_size:
                return None
            value = digest.hexdigest()
            return value if value == _TEST_CODEX_CLIENT_SHA256 else None
        except OSError:
            return None
        finally:
            if descriptor >= 0:
                os.close(descriptor)

    if current_digest() != _TEST_CODEX_CLIENT_SHA256:
        pytest.fail("pinned Codex client input does not match the official ELF digest")
    monkeypatch.setattr(
        runtime_lifecycle, "_canonical_codex_client_path", lambda: client
    )
    monkeypatch.setattr(
        runtime_lifecycle, "_canonical_codex_client_digest", current_digest
    )
    return _TEST_CODEX_CLIENT_SHA256


def _canary_service() -> bytes:
    return (
        (ROOT / "systemd" / "user" / "the-hive-hive-hourly-probe.service")
        .read_bytes()
        .replace(b"@MASTERJET_GENERATION@", _CANARY_GENERATION.encode("ascii"))
        .replace(b"@MASTERJET_MANIFEST_DIGEST@", _CANARY_DIGEST.encode("ascii"))
    )


def _canary_health(code: str) -> bytes:
    ok = {
        "code": "ok",
        "exit_code": 0,
        "stderr": {"state": "empty", "excerpt": "", "redaction_applied": False},
    }
    failed = {
        "code": code,
        "exit_code": None,
        "stderr": {
            "state": "not_returned",
            "excerpt": "",
            "redaction_applied": False,
        },
    }
    return (
        json.dumps(
            {
                "schema_version": 3,
                "checked_at": "2026-09-28T00:00:00+00:00",
                "checks": {
                    "runtime_layout": True,
                    "hive_runtime": False,
                    "hive_doctor": False,
                },
                "commands": {
                    "runtime_status": True,
                    "hive_status": False,
                    "hive_doctor": False,
                },
                "diagnostics": {
                    "runtime_status": ok,
                    "hive_status": failed,
                    "hive_doctor": failed,
                },
                "alarm": {
                    "scope": "hive",
                    "status": "active",
                    "reason_codes": ["hive_doctor", "hive_runtime"],
                    "owner": None,
                },
                "global_pilot_readiness": {
                    "schema_version": 1,
                    "pilot": "blocked",
                    "generation_id": None,
                    "freshness": "unknown",
                    "candidate_count": 0,
                    "reason_codes": ["usage_missing"],
                    "raw_output": "not_returned",
                },
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )


def _canary_green_health() -> bytes:
    payload = json.loads(_canary_health(_CANARY_STAGE_CODES[0]))
    ok = {
        "code": "ok",
        "exit_code": 0,
        "stderr": {"state": "empty", "excerpt": "", "redaction_applied": False},
    }
    payload["checks"] = {
        "runtime_layout": True,
        "hive_runtime": True,
        "hive_doctor": True,
    }
    payload["commands"] = {
        "runtime_status": True,
        "hive_status": True,
        "hive_doctor": True,
    }
    payload["diagnostics"] = {
        "runtime_status": ok,
        "hive_status": ok,
        "hive_doctor": ok,
    }
    payload["alarm"] = {
        "scope": "hive",
        "status": "cleared",
        "reason_codes": [],
        "owner": {
            "principal_id": "canary",
            "class_id": "koenigin",
            "repo_id": "the-hive",
        },
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode() + b"\n"


def _canary_isolated_health() -> bytes:
    payload = json.loads(_canary_green_health())
    payload["checks"] = {
        "runtime_layout": True,
        "hive_runtime": False,
        "hive_doctor": False,
    }
    payload["alarm"] = {
        "scope": "hive",
        "status": "active",
        "reason_codes": ["hive_doctor", "hive_runtime"],
        "owner": {
            "principal_id": "canary",
            "class_id": "koenigin",
            "repo_id": "the-hive",
        },
    }
    payload["global_pilot_readiness"] = {
        "schema_version": 1,
        "pilot": "blocked",
        "generation_id": None,
        "freshness": "unknown",
        "candidate_count": 0,
        "reason_codes": ["usage_generation_missing"],
        "raw_output": "not_returned",
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode() + b"\n"


def _fake_canary_image(root: Path, code: str) -> object:
    release = root / "release"
    state = root / "state"
    release.mkdir(mode=0o700)
    state.mkdir(mode=0o700)
    health = state / "hive-hourly-health.json"
    health.write_bytes(_canary_health(code))
    health.chmod(0o600)
    return runtime_lifecycle._CanaryImage(
        invocation_root=root,
        release_root=release,
        state_root=state,
        generation=_CANARY_GENERATION,
        manifest_digest=_CANARY_DIGEST,
        service=_canary_service(),
    )


def _manager_api_contract_fixture() -> dict[str, object]:
    unit_paths = [
        {
            "dev": None,
            "ino": None,
            "mode": None,
            "path": "/fixture/systemd/user",
            "uid": None,
        }
    ]
    return {
        "api_sha256": "d" * 64,
        "bus": {"dev": 1, "ino": 2, "mode": 0o600, "uid": os.geteuid()},
        "manager": {"features_sha256": "b" * 64, "version": "systemd fixture"},
        "owner": {
            "CGroup": "/user.slice/user-1000.slice/user@1000.service",
            "OwnerUID": str(os.geteuid()),
            "PID": "123",
            "Unit": "user@1000.service",
            "UID": str(os.geteuid()),
            "UniqueName": ":1.23",
        },
        "unit_paths": unit_paths,
        "unit_path_sha256": hashlib.sha256(
            runtime_lifecycle._d320_canonical_json(unit_paths)
        ).hexdigest(),
    }


def _client_metadata_fixture(
    artifact_sha256: str = "a" * 64,
    features_sha256: str = "b" * 64,
    version: str = "codex fixture",
) -> dict[str, object]:
    return {
        "artifact_sha256": artifact_sha256,
        "compatibility_probe": {
            "argv": ["--no-daemon", "features", "list"],
            "config_sha256": {"false": "c" * 64, "true": "d" * 64},
            "exit_codes": {"false": 0, "true": 0},
            "expected": {"false": False, "true": True},
            "observed": {"false": False, "true": True},
            "readback_line_sha256": {"false": "e" * 64, "true": "f" * 64},
            "response_sha256": {"false": "1" * 64, "true": "2" * 64},
            "schema_revision": 1,
        },
        "features_sha256": features_sha256,
        "version": version,
    }


class _CanaryManager:
    def __init__(
        self,
        *,
        foreign: bool = False,
        fail: str | None = None,
        success: bool = False,
    ) -> None:
        self.foreign = foreign
        self.fail = fail
        self.success = success
        self.started = False
        self.stopped = False
        self.reset = False
        self.description = ""
        self.run_calls: list[tuple[str, ...]] = []
        self.systemctl_calls: list[tuple[str, ...]] = []

    def run(self, arguments: tuple[str, ...]) -> dict[str, str]:
        self.run_calls.append(arguments)
        self.description = next(
            value.removeprefix("--description=")
            for value in arguments
            if value.startswith("--description=")
        )
        self.started = True
        if self.fail == "run":
            raise runtime_lifecycle.RuntimeLifecycleError("sensitive-run-detail")
        return {}

    def systemctl(self, arguments: tuple[str, ...]) -> dict[str, str]:
        self.systemctl_calls.append(arguments)
        if arguments[0] == "show":
            if self.foreign:
                return {
                    "LoadState": "loaded",
                    "ActiveState": "active",
                    "Description": "foreign-unit",
                    "Transient": "yes",
                    "Result": "success",
                    "ExecMainStatus": "0",
                }
            if not self.started or self.reset:
                return {
                    "LoadState": "not-found",
                    "ActiveState": "inactive",
                    "Description": "",
                    "Transient": "no",
                    "Result": "success",
                    "ExecMainStatus": "0",
                }
            if self.success:
                return {
                    "LoadState": "loaded",
                    "ActiveState": "active",
                    "Description": self.description,
                    "Transient": "yes",
                    "Result": "success",
                    "ExecMainStatus": "0",
                }
            return {
                "LoadState": "loaded",
                "ActiveState": "failed",
                "Description": self.description,
                "Transient": "yes",
                "Result": "exit-code",
                "ExecMainStatus": "1",
            }
        if arguments[0] == "stop":
            if self.fail == "stop":
                raise runtime_lifecycle.RuntimeLifecycleError("sensitive-stop-detail")
            self.stopped = True
            return {}
        if arguments[0] == "reset-failed":
            if self.fail == "reset-failed":
                raise runtime_lifecycle.RuntimeLifecycleError("sensitive-reset-detail")
            self.reset = True
            return {}
        raise AssertionError(arguments)


def _patch_canary_source(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, code: str
) -> Path:
    runtime_root = tmp_path / "runtime"
    runtime_root.mkdir(mode=0o700)
    monkeypatch.setattr(runtime_lifecycle, "_canary_runtime_root", lambda: runtime_root)
    monkeypatch.setattr(runtime_lifecycle, "_canonical_codex_client_path", lambda: None)
    monkeypatch.setattr(
        runtime_lifecycle,
        "_manager_api_contract_snapshot",
        _manager_api_contract_fixture,
    )
    monkeypatch.setattr(
        runtime_lifecycle,
        "_source_tree_binding",
        lambda _repository: (_CANARY_GENERATION, "c" * 64),
    )

    def prepare(*, repository: Path, invocation_root: Path, source_commit: str):
        assert repository == ROOT
        assert source_commit == _CANARY_GENERATION
        return _fake_canary_image(invocation_root, code)

    monkeypatch.setattr(runtime_lifecycle, "_prepare_canary_image", prepare)
    monkeypatch.setattr(runtime_lifecycle.secrets, "token_hex", lambda _size: "d" * 32)
    return runtime_root


def test_canary_image_is_source_and_manifest_bound(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The disposable image is complete, sealed, and named by clean HEAD."""

    commit = subprocess.run(
        ["git", "-C", str(ROOT), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    monkeypatch.setattr(
        runtime_lifecycle,
        "_source_tree_binding",
        lambda _repository: (commit, "e" * 64),
    )
    invocation = tmp_path / "invocation"
    invocation.mkdir(mode=0o700)
    image = runtime_lifecycle._prepare_canary_image(
        repository=ROOT,
        invocation_root=invocation,
        source_commit=commit,
    )

    from the_hive.runtime_layout import RuntimeLayout

    layout = RuntimeLayout.from_current_release(
        image.release_root, image.generation, image.manifest_digest
    )
    manifest = json.loads(
        (layout.root / ".the-hive-runtime-manifest.json").read_text(encoding="utf-8")
    )
    assert image.generation == commit
    assert manifest["generation"] == commit
    assert manifest["commit"] == commit
    assert image.manifest_digest == layout.manifest_digest
    launcher = (
        image.release_root
        / "generations"
        / image.generation
        / "bin"
        / "the-hive-hive-hourly-probe"
    )
    assert launcher.is_file()
    assert os.access(launcher, os.X_OK)
    assert image.service == layout.read_attested_file(
        "systemd/user/the-hive-hive-hourly-probe.service"
    ).replace(b"@MASTERJET_GENERATION@", commit.encode()).replace(
        b"@MASTERJET_MANIFEST_DIGEST@", image.manifest_digest.encode()
    )


def test_live_canary_fixture_is_digest_bound_and_secret_free() -> None:
    raw = _LIVE_CANARY_FIXTURE.read_bytes()
    assert all(
        marker not in raw
        for marker in (
            b"/home/",
            b"teladi",
            b"Bearer ",
            b'"api_key"',
            b'"access_token"',
        )
    )
    payload = json.loads(raw)
    digest = payload.pop("fixture_digest")
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()

    assert digest == "sha256:" + hashlib.sha256(encoded).hexdigest()
    assert payload["format"] == "the-hive-runtime-live-canary-v1"
    assert payload["consumer_e2e"] == {
        "canonical_artifacts_mutated": False,
        "cleanup_quiescent": True,
        "entrypoint": "scripts/the-hive-runtime-service canary",
        "exit_code": 0,
        "layers": [
            "manager_syntax_transport",
            "namespace_sandbox",
            "helper",
            "product_logic",
        ],
        "result": {
            "error_code": None,
            "raw_output": "not_returned",
            "status": "runtime_canary_green",
        },
    }
    assert payload["redaction"] == {
        "allowlisted_fields": True,
        "contains_absolute_paths": False,
        "contains_account_ids": False,
        "contains_credentials": False,
        "raw_output": "not_returned",
    }


def test_canary_source_binding_rejects_untracked_input(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir(mode=0o700)
    subprocess.run(["git", "init", "-q", repository], check=True)
    tracked = repository / "tracked.txt"
    tracked.write_text("attested\n", encoding="utf-8")
    subprocess.run(["git", "-C", repository, "add", "tracked.txt"], check=True)
    subprocess.run(
        [
            "git",
            "-C",
            repository,
            "-c",
            "user.name=Canary Test",
            "-c",
            "user.email=canary@example.invalid",
            "commit",
            "-q",
            "-m",
            "attested",
        ],
        check=True,
    )

    commit, tree_digest = runtime_lifecycle._source_tree_binding(repository)
    assert len(commit) == 40
    assert len(tree_digest) == 64
    (repository / "untracked.txt").write_text("excluded\n", encoding="utf-8")

    with pytest.raises(
        runtime_lifecycle.RuntimeLifecycleError,
        match="runtime_lifecycle_source_dirty",
    ):
        runtime_lifecycle._source_tree_binding(repository)


def test_canary_unit_preserves_sandbox_and_substitutes_only_private_sources(
    tmp_path: Path,
) -> None:
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    invocation = tmp_path / "invocation"
    invocation.mkdir(mode=0o700)
    image = _fake_canary_image(invocation, _CANARY_STAGE_CODES[0])

    unit = runtime_lifecycle._canary_unit_binding(
        image=image, home=home, nonce="d" * 32
    )
    properties = tuple(unit.properties)
    canonical_state = home / ".local" / "state" / "codex-master-mcp"

    assert unit.name == "the-hive-runtime-canary-" + "d" * 32 + ".service"
    assert f"RuntimeDirectory=the-hive-runtime-canary-{'d' * 32}" in properties
    assert (
        f"BindReadOnlyPaths={image.release_root}:{image.release_root}:norbind"
        in properties
    )
    assert f"BindPaths={image.state_root}:{canonical_state}:norbind" in properties
    assert f"ReadWritePaths={canonical_state}" in properties
    assert "ProtectHome=tmpfs" in properties
    assert "PrivateTmp=yes" in properties
    assert "RemainAfterExit=yes" in properties
    assert "StandardOutput=null" in properties
    assert "StandardError=null" in properties
    assert "TimeoutStartSec=107s" in properties
    assert all("codex-master-openai-pricing" not in value for value in properties)
    assert unit.command == (
        "/usr/bin/bash",
        str(
            image.release_root
            / "generations"
            / _CANARY_GENERATION
            / "bin"
            / "the-hive-hive-hourly-probe"
        ),
        str(image.release_root),
        _CANARY_GENERATION,
        _CANARY_DIGEST,
        "--protected-home-runtime",
        "--json",
    )
    assert "--no-block" in unit.run_arguments
    assert "--wait" not in unit.run_arguments
    assert unit.run_arguments.count(f"--unit={unit.name}") == 1


def test_canary_uses_absolute_manager_sockets_without_runtime_bridge(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Transient properties expose both manager sockets at the UID runtime root."""

    from the_hive import runtime_process

    runtime_root = tmp_path / "run" / "user"
    user_runtime = runtime_root / str(os.geteuid())
    user_runtime.mkdir(parents=True, mode=0o700)
    user_runtime.chmod(0o700)
    monkeypatch.setattr(runtime_lifecycle, "_USER_RUNTIME_DIRECTORY_ROOT", runtime_root)
    monkeypatch.setattr(runtime_process, "_RUNTIME_DIRECTORY_ROOT", runtime_root)
    monkeypatch.setattr(
        runtime_process, "_PROTECTED_HOME_RUNTIME_DIRECTORY", user_runtime
    )
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    invocation = tmp_path / "invocation"
    invocation.mkdir(mode=0o700)
    image = _fake_canary_image(invocation, _CANARY_STAGE_CODES[0])
    first = runtime_lifecycle._canary_unit_binding(
        image=image, home=home, nonce="d" * 32
    )
    second = runtime_lifecycle._canary_unit_binding(
        image=image, home=home, nonce="e" * 32
    )
    first_name = "the-hive-runtime-canary-" + "d" * 32
    second_name = "the-hive-runtime-canary-" + "e" * 32
    assert f"RuntimeDirectory={first_name}" in first.properties
    assert f"RuntimeDirectory={second_name}" in second.properties
    assert not any(
        first_name in value for value in first.properties if value.startswith("Bind")
    )
    assert not any(
        second_name in value for value in second.properties if value.startswith("Bind")
    )
    assert (
        f"BindReadOnlyPaths={user_runtime / 'bus'}:{user_runtime / 'bus'}:norbind"
        in first.properties
    )
    assert (
        "BindReadOnlyPaths="
        f"{user_runtime / 'systemd' / 'private'}:"
        f"{user_runtime / 'systemd' / 'private'}:norbind" in first.properties
    )
    assert all("%t" not in value for value in first.properties)
    environment = runtime_process.minimal_environment(
        home=home, bound_runtime_directory=user_runtime
    )
    assert environment["XDG_RUNTIME_DIR"] == str(user_runtime)


@pytest.mark.parametrize(
    "mutation",
    (
        lambda value: value + b"ReadWritePaths=/foreign\n",
        lambda value: value.replace(
            b"BindReadOnlyPaths=%t/bus:%t/bus:norbind",
            b"BindReadOnlyPaths=%t:/tmp/foreign:norbind",
        ),
        lambda value: value.replace(
            b"BindReadOnlyPaths=%t/systemd/private:%t/systemd/private:norbind",
            b"BindReadOnlyPaths=%t/systemd/private:/tmp/foreign:norbind",
        ),
        lambda value: value.replace(b"ExecStart=", b"ExecStart=/foreign\nExecStart="),
    ),
)
def test_canary_unit_rejects_sandbox_drift(tmp_path: Path, mutation) -> None:
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    invocation = tmp_path / "invocation"
    invocation.mkdir(mode=0o700)
    image = _fake_canary_image(invocation, _CANARY_STAGE_CODES[0])
    image = runtime_lifecycle._CanaryImage(
        invocation_root=image.invocation_root,
        release_root=image.release_root,
        state_root=image.state_root,
        generation=image.generation,
        manifest_digest=image.manifest_digest,
        service=mutation(image.service),
    )

    with pytest.raises(
        runtime_lifecycle.RuntimeLifecycleError,
        match="runtime_canary_sandbox_invalid",
    ):
        runtime_lifecycle._canary_unit_binding(image=image, home=home, nonce="d" * 32)


def test_canary_unit_rejects_a_path_that_systemd_could_reparse(tmp_path: Path) -> None:
    home = tmp_path / "unsafe:home"
    home.mkdir(mode=0o700)
    invocation = tmp_path / "invocation"
    invocation.mkdir(mode=0o700)
    image = _fake_canary_image(invocation, _CANARY_STAGE_CODES[0])

    with pytest.raises(
        runtime_lifecycle.RuntimeLifecycleError,
        match="runtime_canary_sandbox_invalid",
    ):
        runtime_lifecycle._canary_unit_binding(image=image, home=home, nonce="d" * 32)


@pytest.mark.parametrize("code", _CANARY_STAGE_CODES)
def test_canary_returns_each_bounded_preexec_stage_and_quiesces(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, code: str
) -> None:
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    runtime_root = _patch_canary_source(monkeypatch, tmp_path, code)
    manager = _CanaryManager()

    result = runtime_lifecycle.canary(
        home=home, systemctl=manager.systemctl, systemd_run=manager.run
    )

    assert result == {
        "status": "runtime_canary_red",
        "error_code": code,
        "generation": _CANARY_GENERATION,
        "manifest_digest": _CANARY_DIGEST,
        "raw_output": "not_returned",
    }
    assert len(manager.run_calls) == 1
    assert manager.stopped is True
    assert manager.reset is True
    assert not tuple(runtime_root.glob("run-*"))
    touched = " ".join(" ".join(call) for call in manager.systemctl_calls)
    assert "the-hive-hive-hourly-probe" not in touched
    assert "codex-master" not in touched
    assert "pricing" not in touched


def test_canary_unknown_diagnostic_fails_closed_without_returning_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    _patch_canary_source(monkeypatch, tmp_path, "secret-unknown-stage")
    manager = _CanaryManager()

    result = runtime_lifecycle.canary(
        home=home, systemctl=manager.systemctl, systemd_run=manager.run
    )

    assert result["status"] == "runtime_canary_failed"
    assert result["error_code"] == "runtime_canary_evidence_invalid"
    assert "secret" not in json.dumps(result)
    assert manager.stopped is True
    assert manager.reset is True


def test_canary_start_error_still_quiesces_its_attested_transient_unit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    _patch_canary_source(monkeypatch, tmp_path, _CANARY_STAGE_CODES[0])
    manager = _CanaryManager(fail="run")

    result = runtime_lifecycle.canary(
        home=home, systemctl=manager.systemctl, systemd_run=manager.run
    )

    assert result["status"] == "runtime_canary_failed"
    assert result["error_code"] == "runtime_canary_failed"
    assert "sensitive" not in json.dumps(result)
    assert manager.stopped is True
    assert manager.reset is True


def test_canary_manager_wait_is_bounded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    invocation = tmp_path / "invocation"
    invocation.mkdir(mode=0o700)
    binding = runtime_lifecycle._canary_unit_binding(
        image=_fake_canary_image(invocation, _CANARY_STAGE_CODES[0]),
        home=home,
        nonce="d" * 32,
    )
    moments = iter((0.0, runtime_lifecycle._CANARY_RESULT_SECONDS + 1.0))
    monkeypatch.setattr(runtime_lifecycle.time, "monotonic", lambda: next(moments))
    monkeypatch.setattr(runtime_lifecycle.time, "sleep", lambda _seconds: None)

    with pytest.raises(
        runtime_lifecycle.RuntimeLifecycleError,
        match="runtime_canary_timeout",
    ):
        runtime_lifecycle._wait_for_canary_result(
            lambda _arguments: {
                "LoadState": "loaded",
                "ActiveState": "inactive",
                "Description": binding.description,
                "Transient": "yes",
                "Result": "success",
                "ExecMainStatus": "0",
            },
            binding,
        )


def test_canary_green_result_is_bounded_and_quiescent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    runtime_root = _patch_canary_source(monkeypatch, tmp_path, _CANARY_STAGE_CODES[0])

    def prepare(*, repository: Path, invocation_root: Path, source_commit: str):
        image = _fake_canary_image(invocation_root, _CANARY_STAGE_CODES[0])
        health = image.state_root / "hive-hourly-health.json"
        health.write_bytes(_canary_green_health())
        health.chmod(0o600)
        return image

    monkeypatch.setattr(runtime_lifecycle, "_prepare_canary_image", prepare)
    manager = _CanaryManager(success=True)

    result = runtime_lifecycle.canary(
        home=home, systemctl=manager.systemctl, systemd_run=manager.run
    )

    assert result == {
        "status": "runtime_canary_green",
        "error_code": None,
        "generation": _CANARY_GENERATION,
        "manifest_digest": _CANARY_DIGEST,
        "raw_output": "not_returned",
    }
    record = runtime_lifecycle._read_canary_qualification_record(runtime_root)
    assert record is not None
    assert record["status"] == "unqualified"
    assert record["criteria"]["runtime_canary"] == "pass"
    assert record["criteria"]["runtime_features"] == "pass"
    assert record["criteria"]["client_behavior"] == "unknown"
    assert record["criteria"]["manager_actions"] == "unknown"
    assert len(manager.run_calls) == 1
    assert manager.stopped is True
    assert manager.reset is True


def test_client_metadata_probe_executes_pinned_fd_after_path_replacement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "neutral-home"
    home.mkdir(mode=0o700)
    home.chmod(0o700)
    code_home = home / ".codex"
    code_home.mkdir(mode=0o700)
    code_home.chmod(0o700)
    executable = tmp_path / "codex-probe"
    original = (
        b"#!/bin/sh\n"
        b"if [ \"$1\" = --version ]; then printf 'codex 0.fixture\\n'; "
        b'elif [ "$1" = --no-daemon ] && [ "$2" = features ] '
        b'&& [ "$3" = list ]; then '
        b"grep -q '^daemon_auto_start = false$' \"$CODEX_HOME/config.toml\" "
        b"&& { printf 'daemon_auto_start stable false\\n'; exit 0; }; "
        b"grep -q '^daemon_auto_start = true$' \"$CODEX_HOME/config.toml\" "
        b"&& { printf 'daemon_auto_start stable true\\n'; exit 0; }; "
        b"exit 3; else exit 2; fi\n"
    )
    replacement = tmp_path / "codex-replacement"
    replacement.write_bytes(b"#!/bin/sh\nprintf 'replacement\\n'\n")
    replacement.chmod(0o755)
    executable.write_bytes(original)
    executable.chmod(0o755)

    real_popen = runtime_lifecycle.subprocess.Popen
    replaced = False

    def replace_before_exec(*args: object, **kwargs: object) -> subprocess.Popen:
        nonlocal replaced
        if not replaced:
            os.replace(replacement, executable)
            replaced = True
        return real_popen(*args, **kwargs)

    monkeypatch.setattr(runtime_lifecycle.subprocess, "Popen", replace_before_exec)
    result = runtime_lifecycle._probe_codex_client_metadata(
        executable=executable, home=home, codex_home=code_home
    )

    assert replaced
    assert result["version"] == "codex 0.fixture"
    assert result["artifact_sha256"] == hashlib.sha256(original).hexdigest()
    assert result["compatibility_probe"]["observed"] == {
        "false": False,
        "true": True,
    }
    assert result["compatibility_probe"]["argv"] == [
        "--no-daemon",
        "features",
        "list",
    ]
    assert result["compatibility_probe"]["exit_codes"] == {"false": 0, "true": 0}
    assert result["features_status"] == "observed"


def test_client_probe_binds_no_daemon_parser_and_effective_config_readback(
    tmp_path: Path,
) -> None:
    home = tmp_path / "neutral-home"
    home.mkdir(mode=0o700)
    home.chmod(0o700)
    code_home = home / ".codex"
    code_home.mkdir(mode=0o700)
    code_home.chmod(0o700)
    executable = tmp_path / "codex-config-probe"
    executable.write_text(
        "#!/bin/sh\n"
        "if [ \"$1\" = --version ]; then printf 'codex fixture\\n'; exit 0; fi\n"
        'if [ "$1" = --no-daemon ] && [ "$2" = features ] '
        '&& [ "$3" = list ]; then '
        "grep -q '^daemon_auto_start = false$' \"$CODEX_HOME/config.toml\" "
        "&& { printf 'daemon_auto_start stable false\\n'; exit 0; }; "
        "grep -q '^daemon_auto_start = true$' \"$CODEX_HOME/config.toml\" "
        "&& { printf 'daemon_auto_start stable true\\n'; exit 0; }; "
        "exit 3; fi\n"
        "exit 2\n",
        encoding="utf-8",
    )
    executable.chmod(0o755)

    result = runtime_lifecycle._probe_codex_client_metadata(
        executable=executable, home=home, codex_home=code_home
    )

    assert result["compatibility_probe"]["observed"] == {
        "false": False,
        "true": True,
    }
    assert result["compatibility_probe"]["expected"] == {
        "false": False,
        "true": True,
    }
    assert result["compatibility_probe"]["config_sha256"] == {
        "false": hashlib.sha256(b"[features]\ndaemon_auto_start = false\n").hexdigest(),
        "true": hashlib.sha256(b"[features]\ndaemon_auto_start = true\n").hexdigest(),
    }


def test_client_probe_rejects_non_differential_config_readback(
    tmp_path: Path,
) -> None:
    home = tmp_path / "neutral-home"
    home.mkdir(mode=0o700)
    code_home = home / ".codex"
    code_home.mkdir(mode=0o700)
    executable = tmp_path / "codex-static-config-probe"
    executable.write_text(
        "#!/bin/sh\n"
        "if [ \"$1\" = --version ]; then printf 'codex fixture\\n'; exit 0; fi\n"
        'if [ "$1" = --no-daemon ] && [ "$2" = features ] '
        '&& [ "$3" = list ]; then '
        "printf 'daemon_auto_start stable false\\n'; exit 0; fi\n"
        "exit 2\n",
        encoding="utf-8",
    )
    executable.chmod(0o755)

    result = runtime_lifecycle._probe_codex_client_metadata(
        executable=executable, home=home, codex_home=code_home
    )

    assert result["compatibility_probe"] is None
    assert result["no_daemon_status"] == "unknown"
    assert result["config_readback_status"] == "unknown"


def test_client_probe_rejects_cli_that_only_accepts_features_without_no_daemon(
    tmp_path: Path,
) -> None:
    home = tmp_path / "neutral-home"
    home.mkdir(mode=0o700)
    code_home = home / ".codex"
    code_home.mkdir(mode=0o700)
    executable = tmp_path / "codex-flag-reject-probe"
    executable.write_text(
        "#!/bin/sh\n"
        "if [ \"$1\" = --version ]; then printf 'codex fixture\\n'; exit 0; fi\n"
        'if [ "$1" = features ] && [ "$2" = list ]; then '
        "printf 'daemon_auto_start stable false\\n'; exit 0; fi\n"
        "exit 2\n",
        encoding="utf-8",
    )
    executable.chmod(0o755)

    result = runtime_lifecycle._probe_codex_client_metadata(
        executable=executable, home=home, codex_home=code_home
    )

    assert result["compatibility_probe"] is None
    assert result["no_daemon_status"] == "unknown"


def test_client_probe_rejects_codex_home_rebind_during_readback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "neutral-home"
    home.mkdir(mode=0o700)
    code_home = home / ".codex"
    code_home.mkdir(mode=0o700)
    executable = tmp_path / "codex-config-probe"
    executable.write_text(
        "#!/bin/sh\n"
        "if [ \"$1\" = --version ]; then printf 'codex fixture\\n'; exit 0; fi\n"
        'if [ "$1" = --no-daemon ] && [ "$2" = features ] '
        '&& [ "$3" = list ]; then '
        "grep -q '^daemon_auto_start = false$' \"$CODEX_HOME/config.toml\" "
        "&& { printf 'daemon_auto_start stable false\\n'; exit 0; }; "
        "grep -q '^daemon_auto_start = true$' \"$CODEX_HOME/config.toml\" "
        "&& { printf 'daemon_auto_start stable true\\n'; exit 0; }; "
        "exit 3; fi\n"
        "exit 2\n",
        encoding="utf-8",
    )
    executable.chmod(0o755)
    real_run = runtime_lifecycle._run_pinned_client_command
    replaced = False

    def replace_codex_home_after_command(executable_fd, arguments, **kwargs):
        nonlocal replaced
        output = real_run(executable_fd, arguments, **kwargs)
        if arguments == ("--no-daemon", "features", "list") and not replaced:
            os.rename(code_home, home / ".codex-old")
            code_home.mkdir(mode=0o700)
            replaced = True
        return output

    monkeypatch.setattr(
        runtime_lifecycle,
        "_run_pinned_client_command",
        replace_codex_home_after_command,
    )

    result = runtime_lifecycle._probe_codex_client_metadata(
        executable=executable, home=home, codex_home=code_home
    )

    assert replaced
    assert result["compatibility_probe"] is None
    assert result["config_readback_status"] == "unknown"


def test_installed_client_reads_back_private_daemon_config_when_available(
    tmp_path: Path,
) -> None:
    executable = runtime_lifecycle._canonical_codex_client_path()
    if executable is None:
        pytest.skip("fixed canonical Codex executable is unavailable")
    tmp_path.chmod(0o700)
    home = tmp_path / "neutral-home"
    home.mkdir(mode=0o700)
    code_home = home / ".codex"
    code_home.mkdir(mode=0o700)

    observation = runtime_lifecycle._probe_codex_client_metadata(
        executable=executable, home=home, codex_home=code_home
    )

    assert observation["version_status"] == "observed"
    assert observation["features_status"] == "observed"
    assert runtime_lifecycle._valid_client_compatibility_probe(
        observation["compatibility_probe"]
    )
    assert observation["compatibility_probe"]["observed"] == {
        "false": False,
        "true": True,
    }


def test_canary_records_client_metadata_without_claiming_client_behavior(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    runtime_root = _patch_canary_source(monkeypatch, tmp_path, _CANARY_STAGE_CODES[0])

    def prepare(*, repository: Path, invocation_root: Path, source_commit: str):
        image = _fake_canary_image(invocation_root, _CANARY_STAGE_CODES[0])
        health = image.state_root / "hive-hourly-health.json"
        health.write_bytes(_canary_green_health())
        health.chmod(0o600)
        return image

    monkeypatch.setattr(runtime_lifecycle, "_prepare_canary_image", prepare)
    executable = tmp_path / "codex-fixture"
    source = (
        b"#!/bin/sh\n"
        b"if [ \"$1\" = --version ]; then printf 'codex fixture\\n'; "
        b'elif [ "$1" = --no-daemon ] && [ "$2" = features ] '
        b'&& [ "$3" = list ]; then '
        b"grep -q '^daemon_auto_start = false$' \"$CODEX_HOME/config.toml\" "
        b"&& { printf 'daemon_auto_start stable false\\n'; exit 0; }; "
        b"grep -q '^daemon_auto_start = true$' \"$CODEX_HOME/config.toml\" "
        b"&& { printf 'daemon_auto_start stable true\\n'; exit 0; }; "
        b"exit 3; else exit 2; fi\n"
    )
    executable.write_bytes(source)
    executable.chmod(0o755)
    monkeypatch.setattr(
        runtime_lifecycle, "_canonical_codex_client_path", lambda: executable
    )
    monkeypatch.setattr(
        runtime_lifecycle,
        "_canonical_codex_client_digest",
        lambda: hashlib.sha256(source).hexdigest(),
    )

    manager = _CanaryManager(success=True)
    result = runtime_lifecycle.canary(
        home=home, systemctl=manager.systemctl, systemd_run=manager.run
    )

    assert result["status"] == "runtime_canary_green", result
    record = runtime_lifecycle._read_canary_qualification_record(runtime_root)
    assert record is not None
    false_config_sha = hashlib.sha256(
        b"[features]\ndaemon_auto_start = false\n"
    ).hexdigest()
    true_config_sha = hashlib.sha256(
        b"[features]\ndaemon_auto_start = true\n"
    ).hexdigest()
    false_line_sha = hashlib.sha256(b"daemon_auto_start stable false").hexdigest()
    true_line_sha = hashlib.sha256(b"daemon_auto_start stable true").hexdigest()
    false_response_sha = hashlib.sha256(b"daemon_auto_start stable false").hexdigest()
    true_response_sha = hashlib.sha256(b"daemon_auto_start stable true").hexdigest()
    assert record["bindings"]["client"] == {
        "artifact_sha256": hashlib.sha256(source).hexdigest(),
        "compatibility_probe": {
            "argv": ["--no-daemon", "features", "list"],
            "config_sha256": {"false": false_config_sha, "true": true_config_sha},
            "exit_codes": {"false": 0, "true": 0},
            "expected": {"false": False, "true": True},
            "observed": {"false": False, "true": True},
            "readback_line_sha256": {
                "false": false_line_sha,
                "true": true_line_sha,
            },
            "response_sha256": {
                "false": false_response_sha,
                "true": true_response_sha,
            },
            "schema_revision": 1,
        },
        "features_sha256": hashlib.sha256(
            runtime_lifecycle._d320_canonical_json(
                {"false": false_response_sha, "true": true_response_sha}
            )
        ).hexdigest(),
        "version": "codex fixture",
    }
    assert record["criteria"]["client_probe"] == "pass"
    assert record["criteria"]["client_compatibility"] == "pass"
    assert record["status"] == "unqualified"
    assert record["criteria"]["client_behavior"] == "unknown"
    assert record["status"] == "unqualified"


def test_canary_does_not_publish_record_after_manager_api_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    runtime_root = _patch_canary_source(monkeypatch, tmp_path, _CANARY_STAGE_CODES[0])

    def prepare(*, repository: Path, invocation_root: Path, source_commit: str):
        image = _fake_canary_image(invocation_root, _CANARY_STAGE_CODES[0])
        health = image.state_root / "hive-hourly-health.json"
        health.write_bytes(_canary_green_health())
        health.chmod(0o600)
        return image

    monkeypatch.setattr(runtime_lifecycle, "_prepare_canary_image", prepare)
    original = _manager_api_contract_fixture()
    changed = dict(original)
    changed["api_sha256"] = "e" * 64
    observations = iter((original, changed))
    monkeypatch.setattr(
        runtime_lifecycle,
        "_manager_api_contract_snapshot",
        lambda: next(observations),
    )

    manager = _CanaryManager(success=True)
    result = runtime_lifecycle.canary(
        home=home, systemctl=manager.systemctl, systemd_run=manager.run
    )

    assert result["status"] == "runtime_canary_green"
    assert runtime_lifecycle._read_canary_qualification_record(runtime_root) is None


@pytest.mark.parametrize("scenario", ["valid", "signature_drift", "unitpath_rebind"])
def test_manager_api_contract_pins_bus_and_requires_expected_methods(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    scenario: str,
) -> None:
    runtime = tmp_path / "runtime"
    runtime.mkdir(mode=0o700)
    unit_path = tmp_path / "units"
    unit_path.mkdir(mode=0o700)
    bus = runtime / "bus"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(os.fspath(bus))
    monkeypatch.setattr(runtime_lifecycle, "_user_runtime_directory", lambda: runtime)
    methods = {
        "Reload": ("-", "-"),
        "StartUnit": ("ss", "o"),
        "StopUnit": ("ss", "o"),
        "EnableUnitFiles": ("asbb", "ba(sss)"),
        "DisableUnitFiles": ("asb", "a(sss)"),
        "GetUnitFileState": ("s", "s"),
    }
    introspection = "NAME TYPE SIGNATURE RESULT/VALUE FLAGS\n" + "".join(
        f".{name} method {('s' if scenario == 'signature_drift' and name == 'StopUnit' else signature)} {result} -\n"
        for name, (signature, result) in methods.items()
    )
    outputs = {
        "systemctl": (
            f"Version=systemd fixture\nFeatures=+PAM -GCRYPT\nUnitPath={unit_path}\n"
        ).encode(),
        "status": (
            f"PID=123\nUID={os.geteuid()}\nOwnerUID={os.geteuid()}\n"
            "UniqueName=:1.23\nUnit=user@1000.service\n"
            "CGroup=/user.slice/user-1000.slice/user@1000.service\n"
        ).encode(),
        "introspect": introspection.encode(),
    }
    calls: list[tuple[str, ...]] = []

    def fake_run(arguments, **kwargs):
        calls.append(tuple(arguments))
        assert kwargs["pass_fds"] and kwargs["env"][
            "DBUS_SESSION_BUS_ADDRESS"
        ].endswith(f"/proc/self/fd/{kwargs['pass_fds'][0]}")
        if arguments[0].endswith("systemctl"):
            key = "systemctl"
        elif "status" in arguments:
            key = "status"
        else:
            key = "introspect"
            if scenario == "unitpath_rebind":
                os.rename(unit_path, tmp_path / "units-old")
                unit_path.mkdir(mode=0o700)
        return subprocess.CompletedProcess(arguments, 0, outputs[key], b"")

    monkeypatch.setattr(runtime_lifecycle.subprocess, "run", fake_run)
    try:
        result = runtime_lifecycle._manager_api_contract_snapshot()
    finally:
        listener.close()
    if scenario != "valid":
        assert result is None
    else:
        assert runtime_lifecycle._valid_manager_api_contract(result)
        assert result["owner"]["UniqueName"] == ":1.23"
        assert len(calls) == 3


def test_manager_api_contract_rejects_runtime_directory_rebind(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime = tmp_path / "runtime"
    runtime.mkdir(mode=0o700)
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(os.fspath(runtime / "bus"))
    moved = tmp_path / "runtime-old"
    replacement = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    outputs = {
        "systemctl": b"Version=fixture\nFeatures=+PAM\nUnitPath=/run/user/1000/systemd/user\n",
        "status": (
            f"PID=123\nUID={os.geteuid()}\nOwnerUID={os.geteuid()}\n"
            "UniqueName=:1.23\nUnit=user@1000.service\n"
            "CGroup=/user.slice/user-1000.slice/user@1000.service\n"
        ).encode(),
        "introspect": (
            "NAME TYPE SIGNATURE RESULT/VALUE FLAGS\n"
            ".Reload method - - -\n.StartUnit method ss o -\n"
            ".StopUnit method ss o -\n.EnableUnitFiles method asbb ba(sss) -\n"
            ".DisableUnitFiles method asb a(sss) -\n"
            ".GetUnitFileState method s s -\n"
        ).encode(),
    }
    calls = 0

    def fake_run(arguments, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            os.rename(runtime, moved)
            runtime.mkdir(mode=0o700)
            replacement.bind(os.fspath(runtime / "bus"))
        if arguments[0].endswith("systemctl"):
            key = "systemctl"
        elif "status" in arguments:
            key = "status"
        else:
            key = "introspect"
        return subprocess.CompletedProcess(arguments, 0, outputs[key], b"")

    monkeypatch.setattr(runtime_lifecycle, "_user_runtime_directory", lambda: runtime)
    monkeypatch.setattr(runtime_lifecycle.subprocess, "run", fake_run)
    try:
        assert runtime_lifecycle._manager_api_contract_snapshot() is None
    finally:
        listener.close()
        replacement.close()


def test_client_metadata_probe_bounds_child_runtime(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "neutral-home"
    home.mkdir(mode=0o700)
    code_home = home / ".codex"
    code_home.mkdir(mode=0o700)
    executable = tmp_path / "codex-sleeper"
    executable.write_text("#!/bin/sh\nsleep 5\n", encoding="utf-8")
    executable.chmod(0o755)
    monkeypatch.setattr(runtime_lifecycle, "_CANARY_CLIENT_COMMAND_SECONDS", 0.1)

    started = time.monotonic()
    result = runtime_lifecycle._probe_codex_client_metadata(
        executable=executable, home=home, codex_home=code_home
    )

    assert result["version_status"] == "unknown"
    assert result["features_status"] == "unknown"
    assert time.monotonic() - started < 1.0


def test_canary_accepts_exact_fail_closed_empty_private_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    runtime_root = _patch_canary_source(monkeypatch, tmp_path, _CANARY_STAGE_CODES[0])

    def prepare(*, repository: Path, invocation_root: Path, source_commit: str):
        image = _fake_canary_image(invocation_root, _CANARY_STAGE_CODES[0])
        health = image.state_root / "hive-hourly-health.json"
        health.write_bytes(_canary_isolated_health())
        health.chmod(0o600)
        return image

    monkeypatch.setattr(runtime_lifecycle, "_prepare_canary_image", prepare)
    manager = _CanaryManager()

    result = runtime_lifecycle.canary(
        home=home, systemctl=manager.systemctl, systemd_run=manager.run
    )

    assert result == {
        "status": "runtime_canary_green",
        "error_code": None,
        "generation": _CANARY_GENERATION,
        "manifest_digest": _CANARY_DIGEST,
        "raw_output": "not_returned",
    }
    record = runtime_lifecycle._read_canary_qualification_record(runtime_root)
    assert record is not None
    assert record["status"] == "unqualified"
    assert record["criteria"] == {
        "client_behavior": "unknown",
        "client_probe": "unknown",
        "client_compatibility": "unknown",
        "manager_api_contract": "pass",
        "manager_actions": "unknown",
        "runtime_canary": "unknown",
        "runtime_features": "unknown",
    }
    tampered = dict(record)
    tampered["criteria"] = {**record["criteria"], "unreviewed": "pass"}
    with runtime_lifecycle._canary_lock(runtime_root):
        qualification_path = runtime_root / "qualification-v1.json"
        qualification_path.write_bytes(runtime_lifecycle._d320_canonical_json(tampered))
        qualification_path.chmod(0o600)
    with pytest.raises(
        runtime_lifecycle.RuntimeLifecycleError,
        match="runtime_lifecycle_qualification_record_invalid",
    ):
        runtime_lifecycle._read_canary_qualification_record(runtime_root)
    assert manager.stopped is True
    assert manager.reset is True


def test_canary_accepts_a_valid_fail_closed_live_usage_state(tmp_path: Path) -> None:
    invocation = tmp_path / "invocation"
    invocation.mkdir(mode=0o700)
    image = _fake_canary_image(invocation, _CANARY_STAGE_CODES[0])
    payload = json.loads(_canary_isolated_health())
    payload["global_pilot_readiness"] = {
        "schema_version": 1,
        "pilot": "blocked",
        "generation_id": "1" * 32,
        "freshness": "stale",
        "candidate_count": 0,
        "reason_codes": ["usage_stale"],
        "raw_output": "not_returned",
    }
    health = image.state_root / "hive-hourly-health.json"
    health.write_bytes(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    )
    health.chmod(0o600)

    manager_state = {
        "ActiveState": "failed",
        "Result": "exit-code",
        "ExecMainStatus": "1",
    }
    assert runtime_lifecycle._canary_evidence_result(
        image=image, manager_state=manager_state
    ) == ("runtime_canary_green", None)
    assert (
        runtime_lifecycle._canary_runtime_qualification_status(
            image=image, manager_state=manager_state
        )
        == "unknown"
    )


def test_strict_canary_runtime_execution_qualifies_its_runtime_criterion(
    tmp_path: Path,
) -> None:
    invocation = tmp_path / "invocation"
    invocation.mkdir(mode=0o700)
    image = _fake_canary_image(invocation, _CANARY_STAGE_CODES[0])
    health = image.state_root / "hive-hourly-health.json"
    health.write_bytes(_canary_green_health())
    health.chmod(0o600)

    assert (
        runtime_lifecycle._canary_runtime_qualification_status(
            image=image,
            manager_state={
                "ActiveState": "active",
                "Result": "success",
                "ExecMainStatus": "0",
            },
        )
        == "pass"
    )


def test_canary_rejects_a_malformed_fail_closed_readiness_reason(
    tmp_path: Path,
) -> None:
    invocation = tmp_path / "invocation"
    invocation.mkdir(mode=0o700)
    image = _fake_canary_image(invocation, _CANARY_STAGE_CODES[0])
    payload = json.loads(_canary_isolated_health())
    payload["global_pilot_readiness"]["reason_codes"] = ["not-a-valid-reason"]
    health = image.state_root / "hive-hourly-health.json"
    health.write_bytes(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    )
    health.chmod(0o600)

    with pytest.raises(
        runtime_lifecycle.RuntimeLifecycleError,
        match="runtime_canary_evidence_invalid",
    ):
        runtime_lifecycle._canary_evidence_result(
            image=image,
            manager_state={
                "ActiveState": "failed",
                "Result": "exit-code",
                "ExecMainStatus": "1",
            },
        )


def test_canary_source_rebind_stops_before_manager_entry_and_cleans_image(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    runtime_root = tmp_path / "runtime"
    runtime_root.mkdir(mode=0o700)
    monkeypatch.setattr(runtime_lifecycle, "_canary_runtime_root", lambda: runtime_root)
    calls = 0

    def source(_repository: Path) -> tuple[str, str]:
        nonlocal calls
        calls += 1
        return _CANARY_GENERATION, ("c" if calls < 3 else "e") * 64

    monkeypatch.setattr(runtime_lifecycle, "_source_tree_binding", source)
    monkeypatch.setattr(
        runtime_lifecycle,
        "_prepare_canary_image",
        lambda **kwargs: _fake_canary_image(
            kwargs["invocation_root"], _CANARY_STAGE_CODES[0]
        ),
    )
    manager = _CanaryManager()

    result = runtime_lifecycle.canary(
        home=home, systemctl=manager.systemctl, systemd_run=manager.run
    )

    assert result["error_code"] == "runtime_canary_source_changed"
    assert manager.run_calls == []
    assert manager.systemctl_calls == []
    assert not tuple(runtime_root.glob("run-*"))


def test_canary_concurrency_is_rejected_before_image_or_manager_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    runtime_root = _patch_canary_source(monkeypatch, tmp_path, _CANARY_STAGE_CODES[0])
    manager = _CanaryManager()

    with runtime_lifecycle._canary_lock(runtime_root):
        result = runtime_lifecycle.canary(
            home=home, systemctl=manager.systemctl, systemd_run=manager.run
        )

    assert result["status"] == "runtime_canary_failed"
    assert result["error_code"] == "runtime_canary_busy"
    assert manager.run_calls == []
    assert manager.systemctl_calls == []
    assert not tuple(runtime_root.glob("run-*"))


def test_canary_never_changes_canonical_runtime_state_or_pricing_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    canonical = {
        home
        / ".local/lib/the-hive-runtime/.the-hive-release-pointers.json": b"pointer\n",
        home / ".local/state/codex-master-mcp/hive-hourly-health.json": b"health\n",
        home / ".local/state/the-hive/openai-pricing/current.json": b"pricing\n",
        home / ".config/systemd/user/the-hive-hive-hourly-probe.service": b"unit\n",
    }
    for path, content in canonical.items():
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        path.write_bytes(content)
    before = {path: _identity(path) for path in canonical}
    _patch_canary_source(monkeypatch, tmp_path, _CANARY_STAGE_CODES[0])
    manager = _CanaryManager()

    runtime_lifecycle.canary(
        home=home, systemctl=manager.systemctl, systemd_run=manager.run
    )

    assert {path: _identity(path) for path in canonical} == before


@pytest.mark.parametrize("failed_operation", ("stop", "reset-failed", "filesystem"))
def test_canary_cleanup_failure_invalidates_the_diagnosis(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failed_operation: str,
) -> None:
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    _patch_canary_source(monkeypatch, tmp_path, _CANARY_STAGE_CODES[0])
    manager = _CanaryManager(
        fail=failed_operation if failed_operation != "filesystem" else None
    )
    if failed_operation == "filesystem":
        real_rmtree = runtime_lifecycle.shutil.rmtree

        def fail_rmtree(path: Path) -> None:
            if Path(path).name.startswith("run-"):
                raise OSError("sensitive-cleanup-path")
            real_rmtree(path)

        monkeypatch.setattr(runtime_lifecycle.shutil, "rmtree", fail_rmtree)

    result = runtime_lifecycle.canary(
        home=home, systemctl=manager.systemctl, systemd_run=manager.run
    )

    assert result == {
        "status": "runtime_canary_cleanup_failed",
        "error_code": "runtime_canary_cleanup_unverified",
        "generation": _CANARY_GENERATION,
        "manifest_digest": _CANARY_DIGEST,
        "raw_output": "not_returned",
    }
    assert _CANARY_STAGE_CODES[0] not in json.dumps(result)


def test_canary_cleanup_never_uses_historical_ownership_after_show_failure(
    tmp_path: Path,
) -> None:
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    invocation = tmp_path / "invocation"
    invocation.mkdir(mode=0o700)
    binding = runtime_lifecycle._canary_unit_binding(
        image=_fake_canary_image(invocation, _CANARY_STAGE_CODES[0]),
        home=home,
        nonce="d" * 32,
    )
    calls: list[tuple[str, ...]] = []

    def unavailable(arguments: tuple[str, ...]) -> dict[str, str]:
        calls.append(arguments)
        if arguments[0] == "show":
            raise runtime_lifecycle.RuntimeLifecycleError("bounded-show-failure")
        return {}

    cleaned = runtime_lifecycle._cleanup_canary_unit(
        unavailable, binding, ownership_attested=True
    )

    assert cleaned is False
    assert calls == [("show", binding.name, runtime_lifecycle._CANARY_SHOW_PROPERTIES)]


def test_canary_cleanup_rejects_foreign_replacement_between_stop_and_reset(
    tmp_path: Path,
) -> None:
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    invocation = tmp_path / "invocation"
    invocation.mkdir(mode=0o700)
    binding = runtime_lifecycle._canary_unit_binding(
        image=_fake_canary_image(invocation, _CANARY_STAGE_CODES[0]),
        home=home,
        nonce="d" * 32,
    )
    owned = {
        "LoadState": "loaded",
        "ActiveState": "failed",
        "Description": binding.description,
        "Transient": "yes",
        "Result": "exit-code",
        "ExecMainStatus": "1",
    }
    foreign = {**owned, "Description": "foreign replacement"}
    shows = iter((owned, foreign))
    calls: list[tuple[str, ...]] = []

    def replaced(arguments: tuple[str, ...]) -> dict[str, str]:
        calls.append(arguments)
        return next(shows) if arguments[0] == "show" else {}

    cleaned = runtime_lifecycle._cleanup_canary_unit(
        replaced, binding, ownership_attested=True
    )

    assert cleaned is False
    assert ("stop", binding.name) in calls
    assert ("reset-failed", binding.name) not in calls


def test_canary_rejects_a_foreign_unit_without_touching_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    _patch_canary_source(monkeypatch, tmp_path, _CANARY_STAGE_CODES[0])
    manager = _CanaryManager(foreign=True)

    result = runtime_lifecycle.canary(
        home=home, systemctl=manager.systemctl, systemd_run=manager.run
    )

    assert result["status"] == "runtime_canary_failed"
    assert result["error_code"] == "runtime_canary_unit_collision"
    assert manager.run_calls == []
    assert all(call[0] == "show" for call in manager.systemctl_calls)


def test_systemd_run_default_excludes_caller_environment_and_raw_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: dict[str, object] = {}
    monkeypatch.setenv("CANARY_CALLER_SECRET", "must-not-cross")

    def run(command, **kwargs):
        observed["command"] = command
        observed["env"] = kwargs["env"]
        observed["timeout"] = kwargs["timeout"]
        return SimpleNamespace(returncode=1, stdout="raw-secret", stderr="raw-secret")

    monkeypatch.setattr(runtime_lifecycle.subprocess, "run", run)
    with pytest.raises(
        runtime_lifecycle.RuntimeLifecycleError,
        match="runtime_canary_manager_failed",
    ):
        runtime_lifecycle._systemd_run_default(("--unit=safe.service", "/bin/false"))

    assert observed["env"] == {
        "LANG": "C",
        "PATH": "/usr/bin:/bin",
        "XDG_RUNTIME_DIR": f"/run/user/{os.geteuid()}",
        "DBUS_SESSION_BUS_ADDRESS": f"unix:path=/run/user/{os.geteuid()}/bus",
    }
    assert observed["command"][0] == "/usr/bin/systemd-run"
    assert observed["timeout"] == runtime_lifecycle._CANARY_MANAGER_START_SECONDS
    assert "must-not-cross" not in json.dumps(observed)


@pytest.mark.parametrize(
    ("stderr", "expected"),
    (
        (
            "Failed to start transient service unit: Invalid argument\n",
            "runtime_canary_manager_contract_invalid",
        ),
        (
            "Failed to connect to user scope bus via local transport: "
            "Connection refused\n",
            "runtime_canary_manager_unavailable",
        ),
        (
            "Failed to connect to user scope bus via local transport: "
            "No such file or directory\n",
            "runtime_canary_manager_unavailable",
        ),
        (
            "Failed to start transient service unit: Access denied\n",
            "runtime_canary_manager_rejected",
        ),
        (
            "Failed to start transient service unit: Access denied as the "
            "requested operation requires interactive authentication. However, "
            "interactive authentication has not been enabled by the calling "
            "program.\n",
            "runtime_canary_manager_rejected",
        ),
    ),
)
def test_systemd_run_default_classifies_only_fixed_installed_error_forms(
    monkeypatch: pytest.MonkeyPatch, stderr: str, expected: str
) -> None:
    calls = 0

    def run(_command, **_kwargs):
        nonlocal calls
        calls += 1
        return SimpleNamespace(returncode=1, stdout="", stderr=stderr)

    monkeypatch.setattr(runtime_lifecycle.subprocess, "run", run)

    with pytest.raises(runtime_lifecycle.RuntimeLifecycleError) as caught:
        runtime_lifecycle._systemd_run_default(
            ("--unit=sensitive-unit.service", "/sensitive/command")
        )

    assert str(caught.value) == expected
    assert calls == 1
    assert stderr not in repr(caught.value)
    assert "sensitive-unit" not in repr(caught.value)
    assert "/sensitive" not in repr(caught.value)


@pytest.mark.parametrize(
    ("returncode", "stdout", "stderr"),
    (
        (
            1,
            "secret-stdout",
            "Failed to start transient service unit: Invalid argument\n",
        ),
        (
            1,
            "",
            "Failed to start transient service unit: Invalid argument\nsecret-token\n",
        ),
        (
            1,
            "",
            "Failed to start transient service unit: Invalid argument\n"
            "Failed to connect to user scope bus via local transport: "
            "Connection refused\n",
        ),
        (
            1,
            "",
            "Failed to start transient service unit /secret/path: rejected\n",
        ),
        (
            2,
            "",
            "Failed to start transient service unit: Invalid argument\n",
        ),
        (1, "", "secret" * 128),
    ),
)
def test_systemd_run_default_collapses_unknown_or_contradictory_output(
    monkeypatch: pytest.MonkeyPatch, returncode: int, stdout: str, stderr: str
) -> None:
    calls = 0

    def run(_command, **_kwargs):
        nonlocal calls
        calls += 1
        return SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)

    monkeypatch.setattr(runtime_lifecycle.subprocess, "run", run)

    with pytest.raises(runtime_lifecycle.RuntimeLifecycleError) as caught:
        runtime_lifecycle._systemd_run_default(
            ("--unit=sensitive-unit.service", "/sensitive/command")
        )

    assert str(caught.value) == "runtime_canary_manager_failed"
    assert calls == 1
    rendered = repr(caught.value)
    assert stdout not in rendered or not stdout
    assert stderr not in rendered
    assert "secret" not in rendered
    assert "sensitive-unit" not in rendered
    assert "/sensitive" not in rendered


@pytest.mark.parametrize(
    "failure",
    (
        OSError("secret-os-path"),
        subprocess.TimeoutExpired("secret-command", 15, stderr="secret-timeout"),
    ),
)
def test_systemd_run_default_os_and_timeout_failures_remain_unavailable(
    monkeypatch: pytest.MonkeyPatch, failure: BaseException
) -> None:
    calls = 0

    def run(_command, **_kwargs):
        nonlocal calls
        calls += 1
        raise failure

    monkeypatch.setattr(runtime_lifecycle.subprocess, "run", run)

    with pytest.raises(
        runtime_lifecycle.RuntimeLifecycleError,
        match="^runtime_canary_manager_unavailable$",
    ) as caught:
        runtime_lifecycle._systemd_run_default(("--unit=safe.service", "/bin/false"))

    assert calls == 1
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None
    assert "secret" not in repr(caught.value)


@pytest.mark.parametrize(
    "code",
    (
        "runtime_canary_manager_contract_invalid",
        "runtime_canary_manager_rejected",
    ),
)
def test_canary_returns_fixed_manager_start_code_and_still_quiesces(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, code: str
) -> None:
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    _patch_canary_source(monkeypatch, tmp_path, _CANARY_STAGE_CODES[0])
    manager = _CanaryManager()

    def fail_start(arguments: tuple[str, ...]) -> dict[str, str]:
        manager.run(arguments)
        raise runtime_lifecycle.RuntimeLifecycleError(code)

    result = runtime_lifecycle.canary(
        home=home, systemctl=manager.systemctl, systemd_run=fail_start
    )

    assert result == {
        "status": "runtime_canary_failed",
        "error_code": code,
        "generation": _CANARY_GENERATION,
        "manifest_digest": _CANARY_DIGEST,
        "raw_output": "not_returned",
    }
    assert len(manager.run_calls) == 1
    assert manager.stopped is True
    assert manager.reset is True


def test_canary_cleanup_failure_overrides_fixed_manager_start_code(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    _patch_canary_source(monkeypatch, tmp_path, _CANARY_STAGE_CODES[0])
    manager = _CanaryManager(fail="stop")

    def fail_start(arguments: tuple[str, ...]) -> dict[str, str]:
        manager.run(arguments)
        raise runtime_lifecycle.RuntimeLifecycleError(
            "runtime_canary_manager_contract_invalid"
        )

    result = runtime_lifecycle.canary(
        home=home, systemctl=manager.systemctl, systemd_run=fail_start
    )

    assert result == {
        "status": "runtime_canary_cleanup_failed",
        "error_code": "runtime_canary_cleanup_unverified",
        "generation": _CANARY_GENERATION,
        "manifest_digest": _CANARY_DIGEST,
        "raw_output": "not_returned",
    }
    assert len(manager.run_calls) == 1


def _identity(path: Path) -> tuple[int, int, int, int, int, bytes]:
    info = path.stat()
    return (
        info.st_dev,
        info.st_ino,
        info.st_uid,
        info.st_mode & 0o777,
        info.st_nlink,
        path.read_bytes(),
    )


@pytest.mark.parametrize(
    "replacement",
    (
        (
            b"BindReadOnlyPaths=%t/bus:%t/bus:norbind",
            b"BindReadOnlyPaths=%t:/tmp/the-hive-hourly-runtime:norbind",
        ),
        (
            b"BindReadOnlyPaths=%t/systemd/private:%t/systemd/private:norbind",
            b"BindReadOnlyPaths=%t/systemd/private:/tmp/private:norbind",
        ),
        (b"RuntimeDirectory=the-hive-hourly-runtime\n", b""),
        (b"RuntimeDirectoryMode=0700\n", b"RuntimeDirectoryMode=0755\n"),
        (b"--protected-home-runtime --json", b"--json"),
    ),
)
def test_lifecycle_attestation_rejects_missing_protected_home_runtime_contract(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, replacement: tuple[bytes, bytes]
) -> None:
    """A manifest-attested unit still needs the exact protected-home contract."""

    from the_hive import runtime_layout as runtime_layout_module

    old, new = replacement
    service = (
        (ROOT / "systemd" / "user" / "the-hive-hive-hourly-probe.service")
        .read_bytes()
        .replace(old, new)
    )
    timer = (
        ROOT / "systemd" / "user" / "the-hive-hive-hourly-probe.timer"
    ).read_bytes()

    class AttestedLayout:
        def read_attested_file(self, relative: str) -> bytes:
            return {
                "systemd/user/the-hive-hive-hourly-probe.service": service,
                "systemd/user/the-hive-hive-hourly-probe.timer": timer,
            }[relative]

    monkeypatch.setattr(
        runtime_layout_module.RuntimeLayout,
        "from_current_release",
        classmethod(lambda _cls, *_args: AttestedLayout()),
    )

    with pytest.raises(
        runtime_lifecycle.RuntimeLifecycleError,
        match="runtime_lifecycle_postinstall_invalid",
    ):
        runtime_lifecycle._attested_hourly_unit_bytes(
            release_root=tmp_path,
            generation="a" * 40,
            manifest_digest="sha256:" + "b" * 64,
        )


def _lifecycle_state(home: Path) -> None:
    leaf = home / ".local" / "state" / "codex-master-mcp" / "hive"
    leaf.mkdir(parents=True, mode=0o700)
    for directory in (
        home / ".local",
        home / ".local" / "state",
        home / ".local" / "state" / "codex-master-mcp",
        leaf,
    ):
        directory.chmod(0o700)


def _bound_failure_fixture(
    tmp_path: Path,
) -> tuple[runtime_lifecycle._BoundCutover, dict[str, dict[str, str]]]:
    """Create the complete pre-cutover private state for phase-failure tests."""

    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    release = home / ".local" / "lib" / "the-hive-runtime"
    units = home / ".config" / "systemd" / "user"
    state = home / ".local" / "state" / "codex-master-mcp"
    launcher = home / ".local" / "libexec" / "codex_master_hive_hourly_probe.py"
    pricing_launcher = home / ".local" / "bin" / "the-hive-openai-pricing-inventory"
    for directory in (
        home / ".local",
        home / ".local" / "lib",
        release,
        home / ".config",
        home / ".config" / "systemd",
        units,
        home / ".local" / "state",
        state,
        home / ".local" / "libexec",
        home / ".local" / "bin",
    ):
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        directory.chmod(0o700)
    originals = (
        (release / ".the-hive-release-pointers.json", b'{"old":true}\n', 0o644),
        (release / "the-hive-mcp", b"old-mcp\n", 0o755),
        (launcher, b"old-launcher\n", 0o755),
        (pricing_launcher, b"old-pricing-launcher\n", 0o755),
        (state / "runtime-lifecycle-probe-observation.json", b'{"old":true}\n', 0o600),
        (units / "the-hive-hive-hourly-probe.service", b"new-service\n", 0o644),
        (units / "the-hive-hive-hourly-probe.timer", b"new-timer\n", 0o644),
        (units / "the-hive-openai-pricing.service", b"old-pricing-service\n", 0o644),
        (units / "the-hive-openai-pricing.timer", b"old-pricing-timer\n", 0o644),
        (units / "codex-master-hive-hourly-probe.service", b"legacy-service\n", 0o644),
        (units / "codex-master-hive-hourly-probe.timer", b"legacy-timer\n", 0o644),
    )
    for path, content, mode in originals:
        path.write_bytes(content)
        path.chmod(mode)
    states = {
        "the-hive-hive-hourly-probe.service": {
            "LoadState": "loaded",
            "UnitFileState": "disabled",
            "ActiveState": "inactive",
        },
        "the-hive-hive-hourly-probe.timer": {
            "LoadState": "loaded",
            "UnitFileState": "disabled",
            "ActiveState": "inactive",
        },
        "codex-master-hive-hourly-probe.service": {
            "LoadState": "loaded",
            "UnitFileState": "disabled",
            "ActiveState": "active",
        },
        "codex-master-hive-hourly-probe.timer": {
            "LoadState": "loaded",
            "UnitFileState": "enabled",
            "ActiveState": "active",
        },
    }
    return (
        runtime_lifecycle._BoundCutover(
            home=home,
            release_root=release,
            units=units,
            state_root=state,
            files=originals,
            source_digests=(),
            source_commit="a" * 40,
            generations_before=frozenset({"a" * 40}),
            legacy_present=True,
            states=tuple(states.items()),
        ),
        states,
    )


def _mutate_bound_files(bound: runtime_lifecycle._BoundCutover) -> None:
    for path, _content, mode in bound.files:
        path.write_bytes(b"mutated-by-failed-cutover\n")
        path.chmod(mode)


def _assert_bound_files_restored(bound: runtime_lifecycle._BoundCutover) -> None:
    for path, content, mode in bound.files:
        assert content is not None
        device, inode, owner, restored_mode, nlink, bytes_value = _identity(path)
        assert device == path.parent.stat().st_dev
        assert inode > 0
        assert owner == path.parent.stat().st_uid
        assert restored_mode == mode
        assert nlink == 1
        assert bytes_value == content


def _allow_postinstall_attestation(monkeypatch) -> None:
    post_install = object()
    monkeypatch.setattr(
        runtime_lifecycle, "_bind_post_install", lambda _home: post_install
    )
    monkeypatch.setattr(
        runtime_lifecycle, "_revalidate_post_install", lambda _bound, _home: None
    )


def _rollback_restored() -> runtime_lifecycle._RollbackResult:
    return runtime_lifecycle._RollbackResult(True, "complete", "none")


def _cutover_input_home(tmp_path: Path) -> tuple[Path, Path, Path]:
    """Create the private ancestors needed to bind live pricing artifacts."""

    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    release = home / ".local" / "lib" / "the-hive-runtime"
    units = home / ".config" / "systemd" / "user"
    bindir = home / ".local" / "bin"
    for directory in (
        home / ".local",
        home / ".local" / "lib",
        release,
        bindir,
        home / ".config",
        home / ".config" / "systemd",
        units,
    ):
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        directory.chmod(0o700)
    return home, units, bindir


def test_bind_cutover_inputs_snapshots_pricing_artifacts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Pricing artifacts are part of the same rollback witness as Hourly."""

    home, units, bindir = _cutover_input_home(tmp_path)
    launcher = bindir / "the-hive-openai-pricing-inventory"
    service = units / "the-hive-openai-pricing.service"
    timer = units / "the-hive-openai-pricing.timer"
    expected = {
        launcher: (b"old-pricing-launcher\n", 0o755),
        service: (b"old-pricing-service\n", 0o644),
        timer: (b"old-pricing-timer\n", 0o644),
    }
    for path, (content, mode) in expected.items():
        path.write_bytes(content)
        path.chmod(mode)
    monkeypatch.setattr(
        runtime_lifecycle,
        "_source_tree_binding",
        lambda _repository: ("a" * 40, "b" * 64),
    )
    monkeypatch.setattr(runtime_lifecycle, "_source_digest", lambda _path: "c" * 64)

    bound = runtime_lifecycle._bind_cutover_inputs(home)

    snapshots = {path: (content, mode) for path, content, mode in bound.files}
    assert {path: snapshots[path] for path in expected} == expected


@pytest.mark.parametrize(
    ("relative", "mode", "link"),
    [
        (".local/bin/the-hive-openai-pricing-inventory", 0o755, "symlink"),
        (
            ".config/systemd/user/the-hive-openai-pricing.service",
            0o644,
            "hardlink",
        ),
        (
            ".config/systemd/user/the-hive-openai-pricing.timer",
            0o644,
            "symlink",
        ),
    ],
)
def test_bind_cutover_inputs_rejects_unsafe_pricing_targets(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    relative: str,
    mode: int,
    link: str,
) -> None:
    """A pricing target must be absent or an owned single-link regular file."""

    home, _units, _bindir = _cutover_input_home(tmp_path)
    source = tmp_path / "untrusted-pricing-source"
    source.write_bytes(b"untrusted\n")
    source.chmod(mode)
    target = home / relative
    if link == "symlink":
        target.symlink_to(source)
    else:
        target.hardlink_to(source)
    monkeypatch.setattr(
        runtime_lifecycle,
        "_source_tree_binding",
        lambda _repository: ("a" * 40, "b" * 64),
    )
    monkeypatch.setattr(runtime_lifecycle, "_source_digest", lambda _path: "c" * 64)

    with pytest.raises(
        runtime_lifecycle.RuntimeLifecycleError,
        match="^runtime_lifecycle_binding_invalid$",
    ):
        runtime_lifecycle._bind_cutover_inputs(home)


def test_public_runtime_lifecycle_surface_exposes_canary_cutover_status_and_verify() -> (
    None
):
    completed = subprocess.run(
        [SCRIPT, "--help"], check=False, capture_output=True, text=True
    )

    assert completed.returncode == 0
    assert "canary" in completed.stdout
    assert "cutover" in completed.stdout
    assert "status" in completed.stdout
    assert "verify" in completed.stdout
    assert "rollback" not in completed.stdout


def test_public_cutover_without_bound_v2_plan_stops_before_any_effect(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    bound, states = _bound_failure_fixture(tmp_path)
    _lifecycle_state(bound.home)
    lock = bound.state_root / "hive" / ".runtime-lifecycle.lock"
    lock.write_bytes(b"")
    lock.chmod(0o600)
    monkeypatch.setattr(
        runtime_lifecycle,
        "_source_tree_binding",
        lambda _repository: ("a" * 40, "b" * 64),
    )

    manager_calls: list[tuple[str, ...]] = []
    effects: list[str] = []

    def systemctl(arguments: tuple[str, ...]) -> dict[str, str]:
        manager_calls.append(arguments)
        if arguments[0] == "show":
            return states[arguments[1]]
        return {}

    current_cutover = runtime_lifecycle.cutover

    def cli_cutover(*, home: Path, **kwargs: object) -> dict[str, object]:
        return current_cutover(home=home, systemctl=systemctl, **kwargs)

    monkeypatch.setattr(runtime_lifecycle, "cutover", cli_cutover)
    monkeypatch.setattr(
        runtime_lifecycle,
        "_install_attested_runtime",
        lambda _home: effects.append("installer"),
    )
    monkeypatch.setattr(
        runtime_lifecycle,
        "_cutover_systemctl_mutate",
        lambda *_args, **_kwargs: effects.append("manager_mutation"),
    )
    before = {
        str(path.relative_to(bound.home)): (
            path.lstat().st_mode & 0o777,
            path.read_bytes(),
        )
        for path in bound.home.rglob("*")
        if path.is_file()
    }
    monkeypatch.setattr(
        sys,
        "argv",
        [str(SCRIPT), "cutover", "--home", str(bound.home)],
    )

    assert runtime_lifecycle.main() == 1

    result = json.loads(capsys.readouterr().out)
    assert effects == []
    assert result == {
        "raw_output": "not_returned",
        "status": "runtime_lifecycle_plan_required",
    }
    assert manager_calls == []
    after = {
        str(path.relative_to(bound.home)): (
            path.lstat().st_mode & 0o777,
            path.read_bytes(),
        )
        for path in bound.home.rglob("*")
        if path.is_file()
    }
    assert after == before


@pytest.mark.parametrize(
    ("lock_kind", "expected_status"),
    (
        ("held", "runtime_lifecycle_busy"),
        ("symlink", "runtime_lifecycle_store_unavailable"),
    ),
)
def test_public_install_rejects_unavailable_or_untrusted_lifecycle_lock(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    lock_kind: str,
    expected_status: str,
) -> None:
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    hive = home / ".local/state/codex-master-mcp/hive"
    hive.mkdir(mode=0o700, parents=True)
    for directory in (
        home / ".local",
        home / ".local/state",
        home / ".local/state/codex-master-mcp",
        hive,
    ):
        directory.chmod(0o700)
    lock = hive / ".runtime-lifecycle.lock"
    if lock_kind == "held":
        lock.write_bytes(b"")
        lock.chmod(0o600)
    else:
        target = tmp_path / "foreign-lock-target"
        target.write_bytes(b"unmodified\n")
        target.chmod(0o600)
        lock.symlink_to(target)

    monkeypatch.setattr(
        runtime_lifecycle,
        "plan",
        lambda **_kwargs: {
            "status": "runtime_lifecycle_plan_ready",
            "reason_codes": [],
            "plan_sha256": "a" * 64,
            "plan": {"predecessor": {}},
        },
    )
    manager_calls: list[tuple[str, ...]] = []
    installer_calls: list[Path] = []
    monkeypatch.setattr(
        runtime_lifecycle,
        "_install_attested_runtime",
        lambda received, **_kwargs: installer_calls.append(received),
    )
    if lock_kind == "held":
        # A second open file description must not acquire the same transaction lock.
        with lock.open("rb") as owner:
            fcntl.flock(owner.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            result = runtime_lifecycle.cutover(
                home=home,
                plan_sha256="a" * 64,
                phase="install",
                systemctl=lambda arguments: manager_calls.append(arguments) or {},
            )
            fcntl.flock(owner.fileno(), fcntl.LOCK_UN)
    else:
        result = runtime_lifecycle.cutover(
            home=home,
            plan_sha256="a" * 64,
            phase="install",
            systemctl=lambda arguments: manager_calls.append(arguments) or {},
        )
    assert result["status"] == expected_status
    assert manager_calls == []
    assert installer_calls == []
    if lock_kind == "symlink":
        assert lock.is_symlink()
        assert target.read_bytes() == b"unmodified\n"
    assert not (hive / "runtime-lifecycle-journal-v2.json").exists()


@pytest.mark.parametrize(
    "crash_point",
    [
        None,
        "after_setup",
        "actual_preseal",
        "before_setup_callback",
        "before_setup_reservation",
        "after_hook_pin_publish",
        "after_hook_pin_publish_lock_rebind",
        "after_stage_seal",
        "after_publish",
        "after_manager_reload_before_activation",
        "after_legacy_service_stop",
        "after_legacy_timer_disable",
        "after_new_timer_enable",
        "after_manager_reload_after_legacy_removal",
        "observe_failure",
        "root_receipt_missing",
        "plugin_receipt_missing",
        "candidate_manifest_mismatch",
    ],
)
def test_public_install_persists_intent_before_installer_effects(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    crash_point: str | None,
) -> None:
    bound, old_states = _bound_failure_fixture(tmp_path)
    home = bound.home
    monkeypatch.setattr(
        runtime_lifecycle,
        "_source_tree_binding",
        lambda _repository: ("a" * 40, "b" * 64),
    )
    if crash_point != "actual_preseal":
        source_digest = runtime_lifecycle._source_digest
        profile_path = (
            Path(runtime_lifecycle.__file__).resolve().parents[2]
            / "src/the_hive/markdown/runtime-release-compatibility-v1.json"
        )

        def fixture_source_digest(path: Path) -> str:
            if path == profile_path:
                return source_digest(path)
            return "c" * 64

        monkeypatch.setattr(runtime_lifecycle, "_source_digest", fixture_source_digest)
    runtime_identity = {
        "generation": "e" * 40,
        "manifest_digest": "sha256:" + "f" * 64,
        "consumer_pin": True,
        "consumer_sha256": "1" * 64,
    }
    monkeypatch.setattr(
        runtime_lifecycle,
        "_runtime_identity",
        lambda _release_root: dict(runtime_identity),
    )
    qualification_record: dict[str, object] | None = None
    monkeypatch.setattr(
        runtime_lifecycle,
        "_canary_client_metadata",
        lambda _invocation: _client_metadata_fixture(),
    )
    monkeypatch.setattr(
        runtime_lifecycle, "_canonical_codex_client_digest", lambda: "a" * 64
    )
    monkeypatch.setattr(
        runtime_lifecycle,
        "_manager_api_contract_snapshot",
        _manager_api_contract_fixture,
    )
    monkeypatch.setattr(
        runtime_lifecycle,
        "_read_canary_qualification_record",
        lambda _root: qualification_record,
    )
    states = dict(old_states)
    foreign_unit = "unrelated-user-maintenance.service"
    foreign_state = {
        "LoadState": "loaded",
        "UnitFileState": "enabled",
        "ActiveState": "active",
    }
    states[foreign_unit] = dict(foreign_state)
    for unit in runtime_lifecycle._PRICING_UNITS:
        states[unit] = {
            "LoadState": "loaded",
            "UnitFileState": "disabled",
            "ActiveState": "inactive",
        }

    def systemctl(arguments: tuple[str, ...]) -> dict[str, str]:
        return states[arguments[1]] if arguments[0] == "show" else {}

    lifecycle_hive = home / ".local" / "state" / "codex-master-mcp" / "hive"
    assert not lifecycle_hive.exists()
    public_plan = runtime_lifecycle.plan(home=home, systemctl=systemctl)
    assert public_plan["status"] == "runtime_lifecycle_plan_blocked"
    assert not lifecycle_hive.exists()
    public_plan["plan"]["compatibility"] = {
        "status": "qualified",
        "sha256": hashlib.sha256(_CUTOVER_TEST_PROFILE).hexdigest(),
    }
    qualification_record = {
        "bindings": {
            "candidate_generation": "a" * 40,
            "candidate_manifest_digest": "sha256:"
            + ("2" if crash_point == "candidate_manifest_mismatch" else "1") * 64,
            "client": _client_metadata_fixture(),
            "manager_states_sha256": hashlib.sha256(
                runtime_lifecycle._d320_canonical_json(
                    public_plan["plan"]["manager_states"]
                )
            ).hexdigest(),
            "manager_api_contract": _manager_api_contract_fixture(),
            "predecessor": {
                "consumer_sha256": "1" * 64,
                "generation": "e" * 40,
                "manifest_digest": "sha256:" + "f" * 64,
            },
            "profile_sha256": hashlib.sha256(_CUTOVER_TEST_PROFILE).hexdigest(),
            "source_commit": "a" * 40,
            "source_tree_sha256": "b" * 64,
            "target": dict(public_plan["plan"]["target"]),
        },
        "criteria": {
            "client_behavior": "pass",
            "client_probe": "pass",
            "client_compatibility": "pass",
            "manager_api_contract": "pass",
            "manager_actions": "unknown",
            "runtime_canary": "pass",
            "runtime_features": "pass",
        },
        "issued_at_unix_ns": time.time_ns(),
        "owner_uid": os.geteuid(),
        "schema_version": 1,
        "status": "qualified",
    }
    fixture_qualification_record = qualification_record
    public_plan["plan"]["qualification"] = {
        "status": "qualified",
        "issued_at_unix_ns": qualification_record["issued_at_unix_ns"],
        "sha256": hashlib.sha256(
            runtime_lifecycle._d320_canonical_json(qualification_record)
        ).hexdigest(),
    }
    public_plan["plan_sha256"] = hashlib.sha256(
        runtime_lifecycle._d320_canonical_json(public_plan["plan"])
    ).hexdigest()
    public_plan["status"] = "runtime_lifecycle_plan_ready"
    public_plan["reason_codes"] = []
    real_plan = runtime_lifecycle.plan

    def ready_fixture_plan(**kwargs: object) -> dict[str, object]:
        refreshed = real_plan(**kwargs)
        refreshed["plan"]["compatibility"] = {
            "status": "qualified",
            "sha256": hashlib.sha256(_CUTOVER_TEST_PROFILE).hexdigest(),
        }
        refreshed["plan"]["qualification"] = {
            "status": "qualified",
            "issued_at_unix_ns": qualification_record["issued_at_unix_ns"],
            "sha256": hashlib.sha256(
                runtime_lifecycle._d320_canonical_json(qualification_record)
            ).hexdigest(),
        }
        refreshed["plan_sha256"] = hashlib.sha256(
            runtime_lifecycle._d320_canonical_json(refreshed["plan"])
        ).hexdigest()
        if refreshed.get("plan_sha256") == public_plan["plan_sha256"]:
            refreshed["status"] = "runtime_lifecycle_plan_ready"
            refreshed["reason_codes"] = []
        return refreshed

    monkeypatch.setattr(runtime_lifecycle, "plan", ready_fixture_plan)

    observed: list[tuple[str, str]] = []

    class SimulatedProcessCrash(BaseException):
        pass

    def assert_persisted_intent() -> None:
        journal_path = (
            home
            / ".local"
            / "state"
            / "codex-master-mcp"
            / "hive"
            / "runtime-lifecycle-journal-v2.json"
        )
        journal = runtime_lifecycle.D320CutoverJournalV2.from_bytes(
            journal_path.read_bytes()
        )
        assert journal.payload["phase"] == "INTENT"
        observed.append(("intent", journal.payload["phase"]))

    def fake_install(
        install_home: Path,
        *,
        stage_name: str,
        record_setup,
        reserve_setup,
        before_publish,
    ) -> dict[str, str]:
        assert_persisted_intent()
        probe_lock = (
            install_home / ".local/state/codex-master-mcp/.hive-hourly-probe.lock"
        )
        lock_temp = runtime_lifecycle._v2_setup_temp_path(
            runtime_lifecycle._v2_load_journal(install_home).payload, probe_lock
        )
        lock_temp.write_bytes(b"")
        lock_temp.chmod(0o600)
        reserve_setup(
            probe_lock,
            lock_temp,
            runtime_lifecycle._v2_setup_reservation_digest(lock_temp, probe_lock),
        )
        lock_temp.rename(probe_lock)
        stage = install_home / ".local" / "lib" / stage_name
        stage_temp = runtime_lifecycle._v2_setup_temp_path(
            runtime_lifecycle._v2_load_journal(install_home).payload, stage
        )
        stage_temp.mkdir(mode=0o700)
        reserve_setup(
            stage,
            stage_temp,
            runtime_lifecycle._v2_setup_reservation_digest(stage_temp, stage),
        )
        stage_temp.rename(stage)
        record_setup(stage)
        if crash_point == "after_setup":
            raise runtime_lifecycle.RuntimeLifecycleError("simulated_setup_crash")

        class Layout:
            manifest_digest = "sha256:" + "1" * 64

            @staticmethod
            def read_attested_file(relative_path: str) -> bytes:
                assert relative_path == (
                    "src/the_hive/markdown/runtime-release-compatibility-v1.json"
                )
                return _CUTOVER_TEST_PROFILE

        outputs = {
            "mcp_launcher": b"new-mcp\n",
            "hourly_service": b"new-service\n",
            "hourly_timer": b"new-timer\n",
            "pricing_launcher": b"new-pricing-launcher\n",
            "pricing_service": b"new-pricing-service\n",
            "pricing_timer": b"new-pricing-timer\n",
            "legacy_launcher": b"new-legacy-launcher\n",
        }
        generation = (
            install_home
            / ".local"
            / "lib"
            / "the-hive-runtime"
            / "generations"
            / ("a" * 40)
        )
        generation.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        before_publish(
            stage,
            Layout(),
            {key: hashlib.sha256(value).hexdigest() for key, value in outputs.items()},
        )
        if crash_point == "after_stage_seal":
            raise runtime_lifecycle.RuntimeLifecycleError("simulated_stage_crash")
        os.replace(stage, generation)
        targets = {
            "mcp_launcher": install_home
            / ".local"
            / "lib"
            / "the-hive-runtime"
            / "the-hive-mcp",
            "hourly_service": install_home
            / ".config"
            / "systemd"
            / "user"
            / runtime_lifecycle._NEW_SERVICE,
            "hourly_timer": install_home
            / ".config"
            / "systemd"
            / "user"
            / runtime_lifecycle._NEW_TIMER,
            "pricing_launcher": install_home
            / ".local"
            / "bin"
            / runtime_lifecycle._PRICING_LAUNCHER,
            "pricing_service": install_home
            / ".config"
            / "systemd"
            / "user"
            / runtime_lifecycle._PRICING_UNITS[0],
            "pricing_timer": install_home
            / ".config"
            / "systemd"
            / "user"
            / runtime_lifecycle._PRICING_UNITS[1],
            "legacy_launcher": install_home
            / ".local"
            / "libexec"
            / "codex_master_hive_hourly_probe.py",
        }
        for name, path in targets.items():
            path.write_bytes(outputs[name])
            path.chmod(0o644 if name.endswith(("service", "timer")) else 0o755)
        runtime_identity.update(
            generation="a" * 40,
            manifest_digest="sha256:" + "1" * 64,
            consumer_sha256="2" * 64,
        )
        if crash_point == "after_publish":
            raise runtime_lifecycle.RuntimeLifecycleError("simulated_publish_crash")
        return {
            "status": "installed",
            "generation": "a" * 40,
            "manifest_digest": "sha256:" + "1" * 64,
        }

    if crash_point in {
        "actual_preseal",
        "before_setup_callback",
        "before_setup_reservation",
        "after_hook_pin_publish",
        "after_hook_pin_publish_lock_rebind",
    }:
        real_run_path = runpy.run_path
        installer_loads: list[str] = []

        def load_failing_real_installer(path: str, *args: object, **kwargs: object):
            namespace = real_run_path(path, *args, **kwargs)
            if os.fspath(path).startswith("/proc/self/fd/") and callable(
                namespace.get("_install_attested_runtime")
            ):
                installer_loads.append(os.fspath(path))
                globals_map = namespace["_install_attested_runtime"].__globals__
                globals_map["_verified_release_commit"] = lambda _repository: "a" * 40

                if crash_point == "actual_preseal":

                    def fail_after_setup(**_kwargs: object) -> None:
                        raise globals_map["InstallError"](
                            "simulated_preseal_build_failure"
                        )

                    globals_map["_build_runtime_image"] = fail_after_setup
                elif crash_point in {
                    "before_setup_callback",
                    "after_hook_pin_publish",
                    "after_hook_pin_publish_lock_rebind",
                }:
                    original_rename_noreplace = globals_map["_rename_noreplace"]

                    def fail_after_lock_reservation(
                        directory: Path,
                        source: str,
                        target: str,
                        **kwargs: object,
                    ) -> None:
                        if target == ".hive-hourly-probe.lock":
                            if crash_point == "before_setup_callback":
                                raise globals_map["InstallError"](
                                    "simulated_pre_callback_crash"
                                )
                        original_rename_noreplace(directory, source, target, **kwargs)
                        if target == "hook-session-pins-v1" and crash_point in {
                            "after_hook_pin_publish",
                            "after_hook_pin_publish_lock_rebind",
                        }:
                            if crash_point == "after_hook_pin_publish_lock_rebind":
                                lock_path = (
                                    Path(directory)
                                    / target
                                    / ".hook-session-pins-v1.lock"
                                )
                                _replace_file_with_live_inode(lock_path, b"", 0o600)
                            raise SimulatedProcessCrash()

                    globals_map["_rename_noreplace"] = fail_after_lock_reservation
                else:
                    original_setup_directory = globals_map["_setup_directory"]

                    def fail_before_reservation(
                        path: Path,
                        *,
                        mode: int,
                        stage_name: str,
                        reserve_setup,
                    ):
                        def crash_before_record(
                            _path: Path, _temporary: Path, _digest: str
                        ) -> None:
                            raise globals_map["InstallError"](
                                "simulated_unreserved_temp_crash"
                            )

                        return original_setup_directory(
                            path,
                            mode=mode,
                            stage_name=stage_name,
                            reserve_setup=crash_before_record,
                        )

                    globals_map["_setup_directory"] = fail_before_reservation
            return namespace

        monkeypatch.setattr(
            runtime_lifecycle.runpy, "run_path", load_failing_real_installer
        )
    else:
        monkeypatch.setattr(
            runtime_lifecycle, "_install_attested_runtime", fake_install
        )
    launcher_path = home / ".local/lib/the-hive-runtime/the-hive-mcp"
    launcher_before = launcher_path.lstat()
    launcher_bytes_before = launcher_path.read_bytes()
    try:
        result = runtime_lifecycle.cutover(
            home=home,
            plan_sha256=public_plan["plan_sha256"],
            phase="install",
            systemctl=systemctl,
        )
    except SimulatedProcessCrash:
        assert crash_point in {
            "after_hook_pin_publish",
            "after_hook_pin_publish_lock_rebind",
        }
        result = {"status": "simulated_hook_pin_publish_crash"}

    if crash_point == "candidate_manifest_mismatch":
        assert result["status"] == "runtime_lifecycle_qualification_record_changed", (
            result
        )
        assert not (
            home / ".local/lib/the-hive-runtime/generations" / ("a" * 40)
        ).exists()
        launcher_after = launcher_path.lstat()
        assert (launcher_after.st_dev, launcher_after.st_ino) == (
            launcher_before.st_dev,
            launcher_before.st_ino,
        )
        assert launcher_path.read_bytes() == launcher_bytes_before
        return

    if crash_point == "after_setup":
        assert result["status"] == "simulated_setup_crash", result
        interrupted = runtime_lifecycle._v2_load_journal(home)
        assert interrupted.payload["phase"] == "INTENT"
        setup_paths = {
            step["effect"]
            for step in interrupted.payload["steps"]
            if step["action"] == "effect_created"
        }
        stage_path = home / ".local/lib" / interrupted.payload["stage_name"]
        assert (
            str(runtime_lifecycle._v2_setup_temp_path(interrupted.payload, stage_path))
            in setup_paths
        )
        if crash_point in {"actual_preseal", "after_setup"}:
            lock_path = home / ".local/state/codex-master-mcp/.hive-hourly-probe.lock"
            assert (
                str(
                    runtime_lifecycle._v2_setup_temp_path(
                        interrupted.payload, lock_path
                    )
                )
                in setup_paths
            )
        else:
            lock_path = home / ".local/state/codex-master-mcp/.hive-hourly-probe.lock"
            assert (
                str(
                    runtime_lifecycle._v2_setup_temp_path(
                        interrupted.payload, lock_path
                    )
                )
                not in setup_paths
            )
        result = runtime_lifecycle.cutover(
            home=home,
            plan_sha256=public_plan["plan_sha256"],
            phase="recover",
            systemctl=systemctl,
        )
        assert result["status"] == "runtime_lifecycle_recovery_complete", result
        assert not (home / ".local/lib" / interrupted.payload["stage_name"]).exists()
        assert not (
            home / ".local/state/codex-master-mcp/.hive-hourly-probe.lock"
        ).exists()
        return

    if crash_point in {
        "actual_preseal",
        "before_setup_callback",
        "before_setup_reservation",
        "after_hook_pin_publish",
        "after_hook_pin_publish_lock_rebind",
    }:
        if crash_point in {
            "after_hook_pin_publish",
            "after_hook_pin_publish_lock_rebind",
        }:
            assert result["status"] == "simulated_hook_pin_publish_crash"
        else:
            assert result["status"] == "runtime_lifecycle_install_failed", result
        assert installer_loads
        interrupted = runtime_lifecycle._v2_load_journal(home)
        assert interrupted.payload["phase"] == "INTENT"
        setup_paths = {
            step["effect"]
            for step in interrupted.payload["steps"]
            if step["action"] == "effect_created"
        }
        if crash_point == "before_setup_reservation":
            assert not setup_paths
        elif crash_point in {
            "after_hook_pin_publish",
            "after_hook_pin_publish_lock_rebind",
        }:
            for pin_path in (
                home / ".local/state/the-hive",
                home / ".local/state/the-hive/hook-session-pins-v1",
                home
                / ".local/state/the-hive/hook-session-pins-v1/.hook-session-pins-v1.lock",
            ):
                assert (
                    str(
                        runtime_lifecycle._v2_setup_temp_path(
                            interrupted.payload, pin_path
                        )
                    )
                    in setup_paths
                )
        elif crash_point == "actual_preseal":
            lock_path = home / ".local/state/codex-master-mcp/.hive-hourly-probe.lock"
            stage_path = home / ".local/lib" / interrupted.payload["stage_name"]
            assert (
                str(
                    runtime_lifecycle._v2_setup_temp_path(
                        interrupted.payload, lock_path
                    )
                )
                in setup_paths
            )
            assert (
                str(
                    runtime_lifecycle._v2_setup_temp_path(
                        interrupted.payload, stage_path
                    )
                )
                in setup_paths
            )
            for pin_path in (
                home / ".local/state/the-hive",
                home / ".local/state/the-hive/hook-session-pins-v1",
                home
                / ".local/state/the-hive/hook-session-pins-v1/.hook-session-pins-v1.lock",
            ):
                assert (
                    str(
                        runtime_lifecycle._v2_setup_temp_path(
                            interrupted.payload, pin_path
                        )
                    )
                    in setup_paths
                )
        elif crash_point == "before_setup_callback":
            lock_path = home / ".local/state/codex-master-mcp/.hive-hourly-probe.lock"
            stage_path = home / ".local/lib" / interrupted.payload["stage_name"]
            assert (
                str(
                    runtime_lifecycle._v2_setup_temp_path(
                        interrupted.payload, lock_path
                    )
                )
                in setup_paths
            )
            assert (
                str(
                    runtime_lifecycle._v2_setup_temp_path(
                        interrupted.payload, stage_path
                    )
                )
                not in setup_paths
            )
        result = runtime_lifecycle.cutover(
            home=home,
            plan_sha256=public_plan["plan_sha256"],
            phase="recover",
            systemctl=systemctl,
        )
        if crash_point == "after_hook_pin_publish_lock_rebind":
            assert result["status"] == "runtime_lifecycle_recovery_hold", result
            assert (
                home
                / ".local/state/the-hive/hook-session-pins-v1/.hook-session-pins-v1.lock"
            ).is_file()
            assert (home / ".local/state/the-hive/hook-session-pins-v1").is_dir()
            return
        if crash_point == "before_setup_reservation":
            assert result["status"] == "runtime_lifecycle_recovery_hold", result
            assert list(home.rglob(".*.hive-v2-setup-*"))
            return
        assert result["status"] == "runtime_lifecycle_recovery_complete", result
        assert not (
            home / ".local/state/codex-master-mcp/.hive-hourly-probe.lock"
        ).exists()
        assert not (
            home
            / ".local/state/the-hive/hook-session-pins-v1/.hook-session-pins-v1.lock"
        ).exists()
        assert not (home / ".local/state/the-hive/hook-session-pins-v1").exists()
        assert not (home / ".local/state/the-hive").exists()
        if crash_point == "actual_preseal":
            assert not (
                home / ".local/lib" / interrupted.payload["stage_name"]
            ).exists()
        return

    if crash_point in {"after_stage_seal", "after_publish"}:
        assert result["status"] == (
            "simulated_stage_crash"
            if crash_point == "after_stage_seal"
            else "simulated_publish_crash"
        ), result
        interrupted = runtime_lifecycle._v2_load_journal(home)
        assert interrupted.payload["phase"] == "SEALED"
        stage = home / ".local/lib" / interrupted.payload["stage_name"]
        generation = home / ".local/lib/the-hive-runtime/generations" / ("a" * 40)
        assert stage.is_dir() is (crash_point == "after_stage_seal")
        assert generation.is_dir() is (crash_point == "after_publish")
        return

    assert result["status"] == "runtime_lifecycle_install_complete"
    assert (lifecycle_hive / ".runtime-lifecycle.lock").is_file()
    assert observed == [("intent", "INTENT")]
    monkeypatch.setattr(runtime_lifecycle, "plan", real_plan)
    qualification_record = None
    resumed_plan = runtime_lifecycle.plan(home=home, systemctl=systemctl)
    assert resumed_plan["status"] == "runtime_lifecycle_plan_blocked", resumed_plan
    assert (
        "runtime_lifecycle_qualification_record_missing" in resumed_plan["reason_codes"]
    )
    qualification_record = fixture_qualification_record
    monkeypatch.setattr(runtime_lifecycle, "plan", ready_fixture_plan)

    def verified_root_receipt(**kwargs):
        digest = "c" * 64
        if kwargs.get("hold_lock"):
            lock = home / "fixture-root-owner.lock"
            descriptor = os.open(lock, os.O_RDWR | os.O_CREAT, 0o600)
            return digest, descriptor
        return digest

    monkeypatch.setattr(
        runtime_lifecycle,
        "_verify_root_hook_effect_receipt",
        verified_root_receipt,
    )
    monkeypatch.setattr(
        runtime_lifecycle,
        "_verify_plugin_release_effect_receipt",
        lambda **_kwargs: "d" * 64,
    )
    if crash_point == "root_receipt_missing":
        monkeypatch.setattr(
            runtime_lifecycle,
            "_verify_root_hook_effect_receipt",
            lambda **_kwargs: (_ for _ in ()).throw(
                runtime_lifecycle.RuntimeLifecycleError(
                    "runtime_lifecycle_root_hook_effect_unverified"
                )
            ),
        )

    manager_effects: list[tuple[str, ...]] = []

    def mutate_manager(_systemctl, arguments: tuple[str, ...], *, phase: str) -> None:
        journal_before_effect = runtime_lifecycle._v2_load_journal(home)
        assert journal_before_effect.payload["phase"] == "ACTIVATED"
        assert (
            journal_before_effect.payload["steps"][-1]["action"] == "manager_mutation"
        )
        manager_effects.append(arguments)
        if arguments[:2] == ("stop", runtime_lifecycle._LEGACY_SERVICE):
            states[runtime_lifecycle._LEGACY_SERVICE]["ActiveState"] = "inactive"
        elif arguments[:2] == ("disable", "--now"):
            states[runtime_lifecycle._LEGACY_TIMER]["UnitFileState"] = "disabled"
            states[runtime_lifecycle._LEGACY_TIMER]["ActiveState"] = "inactive"
        elif arguments[:2] == ("enable", "--now"):
            states[runtime_lifecycle._NEW_TIMER]["UnitFileState"] = "enabled"
            states[runtime_lifecycle._NEW_TIMER]["ActiveState"] = "active"
        if crash_point == f"after_{phase}":
            raise runtime_lifecycle.RuntimeLifecycleError("simulated_manager_crash")

    monkeypatch.setattr(runtime_lifecycle, "_cutover_systemctl_mutate", mutate_manager)
    activation = runtime_lifecycle.cutover(
        home=home,
        plan_sha256=public_plan["plan_sha256"],
        phase="activate",
        systemctl=systemctl,
    )
    if crash_point == "root_receipt_missing":
        assert activation["status"] == "runtime_lifecycle_root_hook_effect_unverified"
        assert manager_effects == []
        assert runtime_lifecycle._v2_load_journal(home).payload["phase"] == "INSTALLED"
        return

    def restore_manager(_systemctl, arguments: tuple[str, ...]) -> None:
        operation, unit = arguments[0], arguments[-1]
        if operation == "stop":
            states[unit]["ActiveState"] = "inactive"
        elif operation == "start":
            states[unit]["ActiveState"] = "active"
        elif operation == "enable":
            states[unit]["UnitFileState"] = "enabled"
            states[unit]["ActiveState"] = "active"
        elif operation == "disable":
            states[unit]["UnitFileState"] = "disabled"
            states[unit]["ActiveState"] = "inactive"

    monkeypatch.setattr(runtime_lifecycle, "_systemctl_mutate", restore_manager)
    monkeypatch.setattr(
        runtime_lifecycle,
        "_discard_new_generation",
        lambda _bound, **_kwargs: (
            home / ".local/lib/the-hive-runtime/generations" / ("a" * 40)
        ).rmdir(),
    )
    if crash_point not in {None, "observe_failure"}:
        manager_crash_effects = {
            "after_manager_reload_before_activation": "manager:"
            + runtime_lifecycle._NEW_SERVICE,
            "after_legacy_service_stop": "manager:" + runtime_lifecycle._LEGACY_SERVICE,
            "after_legacy_timer_disable": "manager:" + runtime_lifecycle._LEGACY_TIMER,
            "after_new_timer_enable": "manager:" + runtime_lifecycle._NEW_TIMER,
            "after_manager_reload_after_legacy_removal": "manager:"
            + runtime_lifecycle._PRICING_UNITS[0],
        }
        if crash_point in manager_crash_effects:
            assert activation["status"] == "simulated_manager_crash", activation
            interrupted = runtime_lifecycle._v2_load_journal(home)
            assert interrupted.payload["phase"] == "ACTIVATED"
            assert interrupted.payload["steps"][-1]["action"] == "manager_mutation"
            assert (
                interrupted.payload["steps"][-1]["effect"]
                == manager_crash_effects[crash_point]
            )
            expected_commands = {
                "after_manager_reload_before_activation": [("daemon-reload",)],
                "after_legacy_service_stop": [
                    ("daemon-reload",),
                    ("stop", runtime_lifecycle._LEGACY_SERVICE),
                ],
                "after_legacy_timer_disable": [
                    ("daemon-reload",),
                    ("stop", runtime_lifecycle._LEGACY_SERVICE),
                    ("disable", "--now", runtime_lifecycle._LEGACY_TIMER),
                ],
                "after_new_timer_enable": [
                    ("daemon-reload",),
                    ("stop", runtime_lifecycle._LEGACY_SERVICE),
                    ("disable", "--now", runtime_lifecycle._LEGACY_TIMER),
                    ("enable", "--now", runtime_lifecycle._NEW_TIMER),
                ],
                "after_manager_reload_after_legacy_removal": [
                    ("daemon-reload",),
                    ("stop", runtime_lifecycle._LEGACY_SERVICE),
                    ("disable", "--now", runtime_lifecycle._LEGACY_TIMER),
                    ("enable", "--now", runtime_lifecycle._NEW_TIMER),
                    ("daemon-reload",),
                ],
            }
            assert manager_effects == expected_commands[crash_point]
            assert all(foreign_unit not in command for command in manager_effects)

        recovery = runtime_lifecycle.cutover(
            home=home,
            plan_sha256=public_plan["plan_sha256"],
            phase="recover",
            systemctl=systemctl,
        )
        assert recovery["status"] == "runtime_lifecycle_recovery_complete", recovery
        assert (
            runtime_lifecycle._v2_load_journal(home).payload["phase"] == "ROLLED_BACK"
        )
        assert not (
            home / ".local/state/codex-master-mcp/.hive-hourly-probe.lock"
        ).exists()
        assert states == old_states | {
            unit: states[unit] for unit in runtime_lifecycle._PRICING_UNITS
        } | {foreign_unit: foreign_state}
        return
    assert activation["status"] == "runtime_lifecycle_activation_complete", activation
    assert runtime_lifecycle._v2_load_journal(home).payload["phase"] == "ACTIVATED"
    activation_steps = runtime_lifecycle._v2_load_journal(home).payload["steps"]
    assert any(
        step["phase"] == "ACTIVATED"
        and step["action"] == "owner_evidence_readback"
        and step["effect"]
        == str(
            runtime_lifecycle._ROOT_HOOK_ABI_PARENT
            / runtime_lifecycle._ROOT_HOOK_EFFECT_RECEIPT
        )
        and step["sha256"] == "c" * 64
        for step in activation_steps
    )
    assert manager_effects == [
        ("daemon-reload",),
        ("stop", runtime_lifecycle._LEGACY_SERVICE),
        ("disable", "--now", runtime_lifecycle._LEGACY_TIMER),
        ("enable", "--now", runtime_lifecycle._NEW_TIMER),
        ("daemon-reload",),
    ]
    assert all(foreign_unit not in command for command in manager_effects)

    if crash_point == "observe_failure":
        monkeypatch.setattr(
            runtime_lifecycle,
            "_observe_argumentless_installed_probe",
            lambda _home: (_ for _ in ()).throw(
                runtime_lifecycle.RuntimeLifecycleError(
                    "runtime_lifecycle_probe_observation_failed"
                )
            ),
        )
        observation = runtime_lifecycle.cutover(
            home=home,
            plan_sha256=public_plan["plan_sha256"],
            phase="observe",
            systemctl=systemctl,
        )
        assert observation["status"] == "runtime_lifecycle_probe_observation_failed"
        assert runtime_lifecycle._v2_load_journal(home).payload["phase"] == "ACTIVATED"
        monkeypatch.setattr(
            runtime_lifecycle,
            "_discard_new_generation",
            lambda _bound, **_kwargs: (
                home / ".local/lib/the-hive-runtime/generations" / ("a" * 40)
            ).rmdir(),
        )
        recovery = runtime_lifecycle.cutover(
            home=home,
            plan_sha256=public_plan["plan_sha256"],
            phase="recover",
            systemctl=systemctl,
        )
        assert recovery["status"] == "runtime_lifecycle_recovery_complete"
        assert (
            runtime_lifecycle._v2_load_journal(home).payload["phase"] == "ROLLED_BACK"
        )
        assert states == old_states | {
            unit: states[unit] for unit in runtime_lifecycle._PRICING_UNITS
        } | {foreign_unit: foreign_state}
        return

    monkeypatch.setattr(
        runtime_lifecycle, "_observe_argumentless_installed_probe", lambda _home: None
    )
    observation = runtime_lifecycle.cutover(
        home=home,
        plan_sha256=public_plan["plan_sha256"],
        phase="observe",
        systemctl=systemctl,
    )
    assert observation["status"] == "runtime_lifecycle_observation_complete", (
        observation
    )
    observed_journal = runtime_lifecycle._v2_load_journal(home)
    assert observed_journal.payload["phase"] == "OBSERVED"
    assert observed_journal.payload["post"]["manager_states"] == {
        unit: states[unit] for unit in runtime_lifecycle._V2_MANAGER_UNITS
    }
    assert len(observed_journal.payload["post"]["files"]) == len(
        runtime_lifecycle._V2_FILE_PATHS
    )
    assert len(observed_journal.payload["post"]["extra_effects"]) == len(
        runtime_lifecycle._v2_expected_effects(
            home, "a" * 40, observed_journal.payload["stage_name"]
        )
    )
    assert len(observed_journal.payload["post"]["manager_states"]) == 6
    assert sum(
        step["phase"] == "OBSERVED" for step in observed_journal.payload["steps"]
    ) == len(runtime_lifecycle._V2_FILE_PATHS) + len(
        observed_journal.payload["post"]["extra_effects"]
    ) + len(runtime_lifecycle._V2_MANAGER_UNITS)
    if crash_point == "plugin_receipt_missing":
        monkeypatch.setattr(
            runtime_lifecycle,
            "_verify_plugin_release_effect_receipt",
            lambda **_kwargs: (_ for _ in ()).throw(
                runtime_lifecycle.RuntimeLifecycleError(
                    "runtime_lifecycle_plugin_effect_unverified"
                )
            ),
        )
    committed = runtime_lifecycle.cutover(
        home=home,
        plan_sha256=public_plan["plan_sha256"],
        phase="commit",
        systemctl=systemctl,
    )
    if crash_point == "plugin_receipt_missing":
        assert committed["status"] == "runtime_lifecycle_plugin_effect_unverified"
        assert runtime_lifecycle._v2_load_journal(home).payload["phase"] == "OBSERVED"
        assert not any(
            step["phase"] == "OBSERVED" and step["action"] == "owner_evidence_readback"
            for step in runtime_lifecycle._v2_load_journal(home).payload["steps"]
        )
        return
    assert committed["status"] == "runtime_lifecycle_commit_complete", committed
    assert runtime_lifecycle._v2_load_journal(home).payload["phase"] == "COMMITTED"
    committed_steps = runtime_lifecycle._v2_load_journal(home).payload["steps"]
    assert (
        sum(
            step["phase"] == "OBSERVED" and step["action"] == "owner_evidence_readback"
            for step in committed_steps
        )
        == 2
    )


def test_public_plan_is_deterministic_and_reports_missing_profile_without_effects(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    HookSessionPinStoreV1.create_at(
        home / ".local" / "state" / "the-hive" / "hook-session-pins-v1"
    )
    installer = runpy.run_path(
        str(ROOT / "scripts" / "the-hive-hive-hourly-probe-install")
    )
    install_globals = installer["_install_attested_runtime"].__globals__
    install_globals["_verified_release_commit"] = lambda _repository: "a" * 40
    install_globals["_validate_runtime_image_stage"] = lambda **_kwargs: None
    installer["_install_attested_runtime"](
        home=home,
        stage_name=".the-hive-runtime.stage.plan-fixture",
        reserve_setup=lambda _target, _temporary, _digest: None,
        record_setup=lambda _stage: None,
        before_publish=lambda _stage, _layout, _outputs: None,
    )
    _lifecycle_state(home)
    source_root = tmp_path / "source-without-profile"
    for relative in (
        "scripts/the-hive-hive-hourly-probe-install",
        "src/the_hive/usage_snapshot.py",
        "src/the_hive/limit_tracker.py",
        "src/the_hive/runtime_lifecycle.py",
    ):
        source = source_root / relative
        source.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        source.write_text("test source\n", encoding="utf-8")
        source.chmod(0o644)
    monkeypatch.setattr(
        runtime_lifecycle,
        "__file__",
        str(source_root / "src/the_hive/runtime_lifecycle.py"),
    )
    lock = (
        home
        / ".local"
        / "state"
        / "codex-master-mcp"
        / "hive"
        / ".runtime-lifecycle.lock"
    )
    lock.write_bytes(b"")
    lock.chmod(0o600)
    monkeypatch.setattr(
        runtime_lifecycle,
        "_source_tree_binding",
        lambda _repository: ("a" * 40, "b" * 64),
    )

    manager_calls: list[tuple[str, ...]] = []
    manager_drift = {"enabled": False}

    def systemctl(arguments: tuple[str, ...]) -> dict[str, str]:
        manager_calls.append(arguments)
        if arguments[0] == "show":
            return {
                "LoadState": "loaded",
                "UnitFileState": (
                    "enabled"
                    if manager_drift["enabled"]
                    and arguments[1] == "the-hive-hive-hourly-probe.timer"
                    else "disabled"
                ),
                "ActiveState": "inactive",
            }
        return {}

    monkeypatch.setattr(runtime_lifecycle, "_systemctl_default", systemctl)
    before = {
        str(path.relative_to(home)): (
            path.lstat().st_mode & 0o777,
            path.read_bytes(),
        )
        for path in home.rglob("*")
        if path.is_file()
    }

    plans: list[dict[str, object]] = []
    for _ in range(2):
        monkeypatch.setattr(
            sys,
            "argv",
            [str(SCRIPT), "plan", "--home", str(home)],
        )
        assert runtime_lifecycle.main() == 0
        plans.append(json.loads(capsys.readouterr().out))

    assert plans[0] == plans[1]
    assert plans[0]["status"] == "runtime_lifecycle_plan_blocked"
    assert plans[0]["reason_codes"] == [
        "runtime_release_compatibility_profile_missing",
        "runtime_lifecycle_qualification_record_missing",
    ]
    assert len(plans[0]["plan_sha256"]) == 64
    assert all("bytes_b64" not in snapshot for snapshot in plans[0]["plan"]["files"])
    plan_payload = plans[0]["plan"]
    assert len(plan_payload["files"]) == 11
    assert (
        plan_payload["predecessor"]["consumer_sha256"]
        == hashlib.sha256(
            (
                home
                / ".local"
                / "lib"
                / "the-hive-runtime"
                / "generations"
                / plan_payload["predecessor"]["generation"]
                / "src"
                / "the_hive"
                / "usage_snapshot.py"
            ).read_bytes()
        ).hexdigest()
    )
    assert set(plan_payload["manager_states"]) == set(
        runtime_lifecycle._V2_MANAGER_UNITS
    )
    effects = {effect["kind"]: effect for effect in plan_payload["extra_effects"]}
    assert set(effects) == {
        "hook_pin_parent",
        "hook_pin_authority",
        "hook_pin_lock",
        "probe_lock",
        "state_parent",
        "install_state",
        "local_bin",
        "local_libexec",
        "config",
        "config_systemd",
        "units",
        "library",
        "release_root",
        "generations",
        "stage",
        "generation",
        "publish_lock",
        "lifecycle_lock",
        "journal",
    }
    assert effects["stage"] == {
        "kind": "stage",
        "path_template": str(
            home / ".local" / "lib" / ".the-hive-runtime.stage.<transaction-id>"
        ),
    }
    assert effects["generation"]["path"] == str(
        home / ".local" / "lib" / "the-hive-runtime" / "generations" / ("a" * 40)
    )
    predecessor = plan_payload["predecessor"]
    consumer_path = (
        home
        / ".local"
        / "lib"
        / "the-hive-runtime"
        / "generations"
        / predecessor["generation"]
        / "src"
        / "the_hive"
        / "usage_snapshot.py"
    )
    consumer_bytes = consumer_path.read_bytes()
    consumer_path.write_bytes(consumer_bytes + b"\n# fixture drift\n")
    try:
        with pytest.raises(
            runtime_lifecycle.RuntimeLifecycleError,
            match="^runtime_lifecycle_predecessor_changed$",
        ):
            runtime_lifecycle._revalidate_v2_predecessor(
                home / ".local" / "lib" / "the-hive-runtime", predecessor
            )
    finally:
        consumer_path.write_bytes(consumer_bytes)

    manager_drift["enabled"] = True
    monkeypatch.setattr(
        sys,
        "argv",
        [
            str(SCRIPT),
            "cutover",
            "--home",
            str(home),
            "--plan-sha256",
            plans[0]["plan_sha256"],
            "--phase",
            "install",
        ],
    )
    assert runtime_lifecycle.main() == 1
    assert json.loads(capsys.readouterr().out) == {
        "raw_output": "not_returned",
        "status": "runtime_lifecycle_plan_changed",
    }

    manager_drift["enabled"] = False
    monkeypatch.setattr(
        sys,
        "argv",
        [
            str(SCRIPT),
            "cutover",
            "--home",
            str(home),
            "--plan-sha256",
            plans[0]["plan_sha256"],
            "--phase",
            "install",
        ],
    )
    assert runtime_lifecycle.main() == 1
    assert json.loads(capsys.readouterr().out) == {
        "raw_output": "not_returned",
        "reason_codes": [
            "runtime_release_compatibility_profile_missing",
            "runtime_lifecycle_qualification_record_missing",
        ],
        "status": "runtime_lifecycle_plan_blocked",
    }
    assert all(call[0] == "show" for call in manager_calls)
    after = {
        str(path.relative_to(home)): (
            path.lstat().st_mode & 0o777,
            path.read_bytes(),
        )
        for path in home.rglob("*")
        if path.is_file()
    }
    assert after == before


def test_public_plan_holds_for_present_unvalidated_profile_without_effects(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    qualification_root = tmp_path / "uncreated-canary-root"
    monkeypatch.setattr(
        runtime_lifecycle, "_canary_runtime_root", lambda: qualification_root
    )
    HookSessionPinStoreV1.create_at(
        home / ".local" / "state" / "the-hive" / "hook-session-pins-v1"
    )
    installer = runpy.run_path(
        str(ROOT / "scripts" / "the-hive-hive-hourly-probe-install")
    )
    install_globals = installer["_install_attested_runtime"].__globals__
    install_globals["_verified_release_commit"] = lambda _repository: "a" * 40
    install_globals["_validate_runtime_image_stage"] = lambda **_kwargs: None

    source_root = tmp_path / "source"
    for relative in (
        "scripts/the-hive-hive-hourly-probe-install",
        "src/the_hive/usage_snapshot.py",
        "src/the_hive/limit_tracker.py",
        "src/the_hive/runtime_lifecycle.py",
    ):
        source = source_root / relative
        source.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        source.write_text("test source\n", encoding="utf-8")
        source.chmod(0o644)
    candidate_profile = (
        source_root / "src/the_hive/markdown/runtime-release-compatibility-v1.json"
    )
    candidate_profile.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    profile = {
        "observations": [
            {
                "client": {
                    "artifact_sha256": "a" * 64,
                    "features": ["hooks", "resume"],
                    "version": "0.161.0",
                },
                "evidence": {
                    "expires_at_unix_ns": 20,
                    "fixture_sha256": "b" * 64,
                    "observed_at_unix_ns": 10,
                    "source_commit": "c" * 40,
                    "source_tree_sha256": "d" * 64,
                },
                "manager": {"features": ["scopes"], "version": "257.8"},
                "predecessor": {
                    "consumer_sha256": "e" * 64,
                    "generation": "f" * 40,
                    "manifest_digest": "sha256:" + "1" * 64,
                },
                "runtime": {
                    "features": ["resource-gate"],
                    "generation": "2" * 40,
                    "manifest_digest": "sha256:" + "3" * 64,
                },
            }
        ],
        "profile_id": "runtime-release-compatibility-v1",
        "schema_version": 1,
        "status": "unvalidated",
    }
    candidate_profile.write_text(
        json.dumps(profile, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        + "\n",
        encoding="ascii",
    )
    candidate_profile.chmod(0o644)

    build_runtime_image = install_globals["_build_runtime_image"]
    write_runtime_image_manifest = install_globals["_write_runtime_image_manifest"]

    def build_predecessor_without_profile(**kwargs: object) -> None:
        build_runtime_image(**kwargs)  # type: ignore[operator]
        stage = kwargs["stage"]
        profile_path = (
            stage / "src/the_hive/markdown/runtime-release-compatibility-v1.json"
        )
        profile_path.unlink()  # type: ignore[union-attr]
        manifest_path = stage / str(install_globals["_MANIFEST_NAME"])
        manifest_path.unlink()  # type: ignore[union-attr]
        write_runtime_image_manifest(  # type: ignore[operator]
            root=stage,
            generation=kwargs["generation"],
            commit=kwargs["commit"],
        )

    install_globals["_build_runtime_image"] = build_predecessor_without_profile
    monkeypatch.setattr(
        runtime_lifecycle,
        "__file__",
        str(source_root / "src/the_hive/runtime_lifecycle.py"),
    )

    installer["_install_attested_runtime"](
        home=home,
        stage_name=".the-hive-runtime.stage.unvalidated-profile",
        reserve_setup=lambda _target, _temporary, _digest: None,
        record_setup=lambda _stage: None,
        before_publish=lambda _stage, _layout, _outputs: None,
    )
    install_globals["_build_runtime_image"] = build_runtime_image
    _lifecycle_state(home)
    lock = (
        home
        / ".local"
        / "state"
        / "codex-master-mcp"
        / "hive"
        / ".runtime-lifecycle.lock"
    )
    lock.write_bytes(b"")
    lock.chmod(0o600)
    monkeypatch.setattr(
        runtime_lifecycle,
        "_source_tree_binding",
        lambda _repository: ("a" * 40, "b" * 64),
    )

    manager_calls: list[tuple[str, ...]] = []

    def systemctl(arguments: tuple[str, ...]) -> dict[str, str]:
        manager_calls.append(arguments)
        if arguments[0] == "show":
            return {
                "LoadState": "loaded",
                "UnitFileState": "disabled",
                "ActiveState": "inactive",
            }
        return {}

    monkeypatch.setattr(runtime_lifecycle, "_systemctl_default", systemctl)
    before = {
        str(path.relative_to(home)): (path.lstat().st_mode & 0o777, path.read_bytes())
        for path in home.rglob("*")
        if path.is_file()
    }
    monkeypatch.setattr(sys, "argv", [str(SCRIPT), "plan", "--home", str(home)])

    assert runtime_lifecycle.main() == 0
    result = json.loads(capsys.readouterr().out)

    assert result["status"] == "runtime_lifecycle_plan_blocked"
    assert result["reason_codes"] == [
        "runtime_release_compatibility_profile_unvalidated",
        "runtime_lifecycle_qualification_record_missing",
    ]
    assert result["plan"]["compatibility"]["status"] == "present_unvalidated"
    assert len(result["plan"]["compatibility"]["sha256"]) == 64
    current = runtime_lifecycle._runtime_identity(home / ".local/lib/the-hive-runtime")
    assert isinstance(current, dict)
    predecessor_profile = (
        home
        / ".local/lib/the-hive-runtime/generations"
        / current["generation"]
        / "src/the_hive/markdown/runtime-release-compatibility-v1.json"
    )
    assert not predecessor_profile.exists()
    assert all(call[0] == "show" for call in manager_calls)
    assert not qualification_root.exists()
    plan_source = result["plan"]["source"]
    plan_predecessor = result["plan"]["predecessor"]
    stale_record = {
        "bindings": {
            "candidate_generation": plan_source["commit"],
            "candidate_manifest_digest": "sha256:" + "c" * 64,
            "client": None,
            "manager_states_sha256": hashlib.sha256(
                runtime_lifecycle._d320_canonical_json(result["plan"]["manager_states"])
            ).hexdigest(),
            "manager_api_contract": _manager_api_contract_fixture(),
            "predecessor": {
                key: plan_predecessor[key]
                for key in ("consumer_sha256", "generation", "manifest_digest")
            },
            "profile_sha256": result["plan"]["compatibility"]["sha256"],
            "source_commit": plan_source["commit"],
            "source_tree_sha256": plan_source["tree_sha256"],
            "target": dict(result["plan"]["target"]),
        },
        "criteria": {
            "client_behavior": "unknown",
            "client_probe": "unknown",
            "client_compatibility": "unknown",
            "manager_api_contract": "unknown",
            "manager_actions": "unknown",
            "runtime_canary": "pass",
            "runtime_features": "unknown",
        },
        "issued_at_unix_ns": time.time_ns()
        - runtime_lifecycle._OWNER_RECEIPT_FRESHNESS_NS
        - 1,
        "owner_uid": os.geteuid(),
        "schema_version": 1,
        "status": "unqualified",
    }
    qualification_root.mkdir(mode=0o700)
    with runtime_lifecycle._canary_lock(qualification_root) as canary_lock_fd:
        runtime_lifecycle._publish_canary_qualification_record(
            root=qualification_root, lock_fd=canary_lock_fd, value=stale_record
        )
    assert runtime_lifecycle.main() == 0
    stale_result = json.loads(capsys.readouterr().out)
    assert stale_result["reason_codes"] == [
        "runtime_release_compatibility_profile_unvalidated",
        "runtime_lifecycle_qualification_record_expired",
    ]
    after = {
        str(path.relative_to(home)): (path.lstat().st_mode & 0o777, path.read_bytes())
        for path in home.rglob("*")
        if path.is_file()
    }
    assert after == before


def test_stage_profile_member_must_match_bound_plan_digest(tmp_path: Path) -> None:
    from the_hive.runtime_layout import RuntimeLayout

    installer = runpy.run_path(
        str(ROOT / "scripts" / "the-hive-hive-hourly-probe-install")
    )
    stage = tmp_path / "stage"
    stage.mkdir(mode=0o700)
    installer["_build_runtime_image"](
        repository=ROOT,
        stage=stage,
        generation="a" * 40,
        commit="a" * 40,
    )
    profile_path = stage / "src/the_hive/markdown/runtime-release-compatibility-v1.json"
    profile_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    raw = b"candidate profile bytes\n"
    profile_path.write_bytes(raw)
    profile_path.chmod(0o644)
    (stage / installer["_MANIFEST_NAME"]).unlink()
    installer["_write_runtime_image_manifest"](
        root=stage, generation="a" * 40, commit="a" * 40
    )
    layout = RuntimeLayout.from_runtime_root(stage)

    runtime_lifecycle._verify_candidate_compatibility_profile_stage(
        layout, hashlib.sha256(raw).hexdigest()
    )
    with pytest.raises(
        runtime_lifecycle.RuntimeLifecycleError,
        match="^runtime_lifecycle_compatibility_profile_changed$",
    ):
        runtime_lifecycle._verify_candidate_compatibility_profile_stage(
            layout, hashlib.sha256(b"different candidate bytes\n").hexdigest()
        )


def test_legacy_installer_cli_rejects_a_second_mutating_operator_route(
    tmp_path: Path,
) -> None:
    completed = subprocess.run(
        [
            ROOT / "scripts" / "the-hive-hive-hourly-probe-install",
            "--home",
            tmp_path / "home",
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 1
    assert completed.stdout == (
        '{"raw_output": "not_returned", '
        '"status": "runtime_lifecycle_cutover_required"}\n'
    )
    assert not (tmp_path / "home").exists()


def test_systemctl_default_uses_only_the_canonical_uid_user_manager_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """User-manager routing is UID-derived, bounded, and caller-independent."""

    calls: list[tuple[list[str], dict[str, object]]] = []
    arguments = (
        "show",
        "the-hive-hive-hourly-probe.service",
        "--property=LoadState,UnitFileState,ActiveState,Result,ExecMainStatus",
    )
    monkeypatch.setenv("DBUS_SESSION_BUS_ADDRESS", "unix:path=/hostile/bus")
    monkeypatch.setenv("XDG_RUNTIME_DIR", "/hostile/runtime")
    monkeypatch.setenv("PATH", "/hostile/bin")
    monkeypatch.setattr(runtime_lifecycle.os, "geteuid", lambda: 4242)

    def fake_run(argv: list[str], **kwargs: object) -> SimpleNamespace:
        calls.append((argv, kwargs))
        return SimpleNamespace(
            returncode=0,
            stdout=(
                "LoadState=loaded\n"
                "UnitFileState=disabled\n"
                "ActiveState=inactive\n"
                "Result=success\n"
                "ExecMainStatus=0\n"
            ),
        )

    monkeypatch.setattr(runtime_lifecycle.subprocess, "run", fake_run)

    assert runtime_lifecycle._systemctl_default(arguments) == {
        "LoadState": "loaded",
        "UnitFileState": "disabled",
        "ActiveState": "inactive",
        "Result": "success",
        "ExecMainStatus": "0",
    }
    assert calls == [
        (
            ["/usr/bin/systemctl", "--user", "--no-pager", *arguments],
            {
                "check": False,
                "stdin": subprocess.DEVNULL,
                "capture_output": True,
                "text": True,
                "timeout": 15,
                "env": {
                    "LANG": "C",
                    "PATH": "/usr/bin:/bin",
                    "XDG_RUNTIME_DIR": "/run/user/4242",
                    "DBUS_SESSION_BUS_ADDRESS": "unix:path=/run/user/4242/bus",
                },
            },
        )
    ]


def test_systemctl_default_keeps_a_nonzero_systemctl_result_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        runtime_lifecycle.subprocess,
        "run",
        lambda *_arguments, **_kwargs: SimpleNamespace(returncode=1, stdout=""),
    )

    with pytest.raises(
        runtime_lifecycle.RuntimeLifecycleError,
        match="^runtime_lifecycle_systemd_failed$",
    ):
        runtime_lifecycle._systemctl_default(("show", "missing.service"))


def test_d300_consumer_producer_contract_accepts_only_named_06542_identity() -> None:
    """Catches a runtime image that retains the retired .541 pin or a fallback."""

    valid = (
        b'_PRODUCER_VERSION = "0.6.542"\n'
        b'_PRODUCER_SOURCE_MANIFEST_SHA256 = "d08706fbbc4e7b99c769787e42dd4c4ef4b956b1e3ec8fb0175acb8c58c566b6"\n'
        b'_PRODUCER_RELEASE_ID = "0.6.542-d08706fbbc4e7b99"\n'
        b'if python_directory[2] != "python3.14":\n    raise ValueError()\n'
    )
    retired = valid.replace(b'"0.6.542"', b'"0.6.541"')
    other_version = valid.replace(b'"0.6.542"', b'"0.6.543"')
    other_manifest = valid.replace(
        b"d08706fbbc4e7b99c769787e42dd4c4ef4b956b1e3ec8fb0175acb8c58c566b6",
        b"0" * 64,
    )
    heuristic_only = b"# " + valid

    assert runtime_lifecycle._consumer_producer_contract(valid) is True
    assert runtime_lifecycle._consumer_producer_contract(retired) is False
    assert runtime_lifecycle._consumer_producer_contract(other_version) is False
    assert runtime_lifecycle._consumer_producer_contract(other_manifest) is False
    assert runtime_lifecycle._consumer_producer_contract(heuristic_only) is False


def test_d296_accepts_attested_mixed_availability_without_granting_authority(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    accounts = (
        "BW_Nufker",
        "BW_Privat",
        "BW_Work",
        "Birthe_Privat",
        "GPT1",
        "RH_Privat",
    )
    authorities = tuple(
        usage_snapshot.PoolAuthorityV2(
            account_id=account,
            pool_id="openai",
            provider="openai",
            allowed_lifecycles=("ephemeral", "persistent", "session"),
            allowed_model_families=("luna", "sol", "terra"),
            hive_available=index != 1,
            persistent_leadership_eligible=index != 1,
            long_running_leadership_eligible=index != 1,
            reasoning_minimum="low",
            reasoning_maximum="max",
        )
        for index, account in enumerate(accounts)
    )
    evidence = usage_snapshot.UsageEvidenceV2((), "stale", None, None, authorities)
    monkeypatch.setattr(usage_snapshot, "read_usage_evidence_v2", lambda: evidence)

    assert runtime_lifecycle._d296_and_v2_accepted() is True

    inconsistent = list(authorities)
    inconsistent[1] = replace(inconsistent[1], persistent_leadership_eligible=True)
    monkeypatch.setattr(
        usage_snapshot,
        "read_usage_evidence_v2",
        lambda: usage_snapshot.UsageEvidenceV2(
            (), "stale", None, None, tuple(inconsistent)
        ),
    )
    assert runtime_lifecycle._d296_and_v2_accepted() is False


def test_verify_is_read_only_and_reports_separate_timer_states(tmp_path: Path) -> None:
    home = tmp_path / "home"
    units = home / ".config" / "systemd" / "user"
    units.mkdir(parents=True, mode=0o700)
    timer = units / "the-hive-hive-hourly-probe.timer"
    timer.write_text(
        "[Timer]\n"
        "OnCalendar=*-*-* 00,03,06,09,12,15,18,21:00:00 UTC\n"
        "[Install]\nWantedBy=timers.target\n",
        encoding="utf-8",
    )
    timer.chmod(0o644)
    (units / "the-hive-hive-hourly-probe.service").write_text(
        "[Service]\nType=oneshot\n", encoding="utf-8"
    )
    (units / "the-hive-hive-hourly-probe.service").chmod(0o644)
    calls: list[tuple[str, ...]] = []

    def systemctl(arguments: tuple[str, ...]) -> dict[str, str]:
        calls.append(arguments)
        assert arguments[0] == "show"
        return {
            "LoadState": "loaded",
            "UnitFileState": "enabled",
            "ActiveState": "active",
            "Result": "success",
            "ExecMainStatus": "0",
        }

    result = runtime_lifecycle.verify(home=home, systemctl=systemctl)

    assert result["installed"] is False
    assert result["enabled"] is False
    assert result["active"] is False
    assert result["observed"] is False
    assert result["error_code"] == "runtime_lifecycle_runtime_identity_invalid"
    assert result["status"] == "runtime_lifecycle_red"
    assert calls == []


def test_verify_rejects_a_timer_with_any_term_beyond_the_exact_eight_utc_contract(
    tmp_path: Path,
) -> None:
    home = tmp_path / "home"
    units = home / ".config" / "systemd" / "user"
    units.mkdir(parents=True, mode=0o700)
    timer = units / "the-hive-hive-hourly-probe.timer"
    timer.write_text(
        "[Timer]\n"
        "OnCalendar=*-*-* 00,03,06,09,12,15,18,21:00:00 UTC\n"
        "OnCalendar=*-*-* 01:00:00 UTC\n",
        encoding="utf-8",
    )
    timer.chmod(0o644)
    (units / "the-hive-hive-hourly-probe.service").write_text(
        "[Service]\n", encoding="utf-8"
    )
    (units / "the-hive-hive-hourly-probe.service").chmod(0o644)

    result = runtime_lifecycle.verify(
        home=home,
        systemctl=lambda _arguments: {
            "LoadState": "not-found",
            "UnitFileState": "disabled",
            "ActiveState": "inactive",
            "Result": "success",
            "ExecMainStatus": "0",
        },
    )

    assert result["checks"]["eight_utc_terms"] is False


def test_verify_rejects_hardlinked_or_symlinked_unit_files(tmp_path: Path) -> None:
    home = tmp_path / "home"
    units = home / ".config" / "systemd" / "user"
    units.mkdir(parents=True, mode=0o700)
    source = tmp_path / "unit-source"
    source.write_text(
        "[Timer]\nOnCalendar=*-*-* 00,03,06,09,12,15,18,21:00:00 UTC\n",
        encoding="utf-8",
    )
    source.chmod(0o644)
    (units / "the-hive-hive-hourly-probe.timer").hardlink_to(source)
    (units / "the-hive-hive-hourly-probe.service").symlink_to(source)

    result = runtime_lifecycle.verify(
        home=home,
        systemctl=lambda _arguments: {
            "LoadState": "not-found",
            "UnitFileState": "disabled",
            "ActiveState": "inactive",
            "Result": "failed",
            "ExecMainStatus": "1",
        },
    )

    assert result["installed"] is False
    assert result["checks"]["unit_files"] is False


def test_verify_returns_a_stable_binding_error_without_later_unbound_reads(
    tmp_path: Path,
) -> None:
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    target = tmp_path / "untrusted-units"
    target.mkdir(mode=0o700)
    units_parent = home / ".config" / "systemd"
    units_parent.mkdir(parents=True, mode=0o700)
    for directory in (home / ".config", units_parent):
        directory.chmod(0o700)
    (units_parent / "user").symlink_to(target)
    calls: list[tuple[str, ...]] = []

    result = runtime_lifecycle.verify(
        home=home, systemctl=lambda arguments: calls.append(arguments) or {}
    )

    assert result["status"] == "runtime_lifecycle_red"
    assert result["error_code"] == "runtime_lifecycle_binding_invalid"
    assert result["installed"] is False
    assert result["enabled"] is False
    assert result["active"] is False
    assert result["observed"] is False
    assert calls == []


@pytest.mark.parametrize(
    ("service_bytes", "timer_bytes"),
    (
        (
            b"[Service]\nExecStart=/malicious\n",
            b"[Timer]\nOnCalendar=*-*-* 00,03,06,09,12,15,18,21:00:00 UTC\n",
        ),
        (
            b"[Service]\nExecStart=/attested\n",
            (
                b"[Timer]\nOnCalendar=*-*-* 00,03,06,09,12,15,18,21:00:00 UTC\n"
                b"Persistent=false\nUnit=malicious.service\n"
            ),
        ),
    ),
    ids=("malicious-service", "eight-term-timer-wrong-semantics"),
)
def test_verify_rejects_units_not_exactly_derived_from_attested_runtime(
    tmp_path: Path, monkeypatch, service_bytes: bytes, timer_bytes: bytes
) -> None:
    home = tmp_path / "home"
    units = home / ".config" / "systemd" / "user"
    units.mkdir(parents=True, mode=0o700)
    for directory in (home, home / ".config", home / ".config" / "systemd", units):
        directory.chmod(0o700)
    (units / "the-hive-hive-hourly-probe.service").write_bytes(service_bytes)
    (units / "the-hive-hive-hourly-probe.timer").write_bytes(timer_bytes)
    for path in units.iterdir():
        path.chmod(0o644)
    identity = {
        "generation": "a" * 40,
        "manifest_digest": "sha256:" + "b" * 64,
        "consumer_pin": True,
    }
    monkeypatch.setattr(runtime_lifecycle, "_runtime_identity", lambda _root: identity)
    monkeypatch.setattr(
        runtime_lifecycle,
        "_attested_hourly_unit_bytes",
        lambda **_kwargs: (
            b"[Service]\nExecStart=/attested\n",
            b"[Timer]\nOnCalendar=*-*-* 00,03,06,09,12,15,18,21:00:00 UTC\n",
        ),
    )
    monkeypatch.setattr(runtime_lifecycle, "_d296_and_v2_accepted", lambda: True)
    monkeypatch.setattr(
        runtime_lifecycle, "_parse_health", lambda _root: (True, True, True)
    )
    monkeypatch.setattr(runtime_lifecycle, "_probe_gate_allowed", lambda _root: True)
    monkeypatch.setattr(
        runtime_lifecycle, "_observation_matches", lambda **_kwargs: True
    )
    calls: list[tuple[str, ...]] = []

    result = runtime_lifecycle.verify(
        home=home, systemctl=lambda arguments: calls.append(arguments) or {}
    )

    assert result["status"] == "runtime_lifecycle_red"
    assert result["error_code"] == "runtime_lifecycle_unit_attestation_invalid"
    assert result["checks"]["unit_files"] is False
    assert calls == []


def test_not_found_systemd_unit_accepts_empty_unit_file_state() -> None:
    assert runtime_lifecycle._valid_bound_unit_state(
        {
            "LoadState": "not-found",
            "UnitFileState": "",
            "ActiveState": "inactive",
            "Result": "success",
            "ExecMainStatus": "0",
        }
    )


def test_lifecycle_lock_creates_only_the_missing_private_hive_leaf(
    tmp_path: Path,
) -> None:
    home = tmp_path / "home"
    parent = home / ".local" / "state" / "codex-master-mcp"
    parent.mkdir(parents=True, mode=0o700)
    for directory in (
        home / ".local",
        home / ".local" / "state",
        parent,
    ):
        directory.chmod(0o700)

    with runtime_lifecycle._lifecycle_lock(home):
        lock = parent / "hive" / ".runtime-lifecycle.lock"
        assert lock.is_file()
        assert lock.lstat().st_mode & 0o777 == 0o600

    assert (parent / "hive").lstat().st_mode & 0o777 == 0o700


def test_verify_never_derives_observation_from_systemd_health_or_gate(
    tmp_path: Path, monkeypatch
) -> None:
    home = tmp_path / "home"
    units = home / ".config" / "systemd" / "user"
    units.mkdir(parents=True, mode=0o700)
    for name, text in (
        ("the-hive-hive-hourly-probe.service", "[Service]\n"),
        (
            "the-hive-hive-hourly-probe.timer",
            "[Timer]\nOnCalendar=*-*-* 00,03,06,09,12,15,18,21:00:00 UTC\n",
        ),
    ):
        path = units / name
        path.write_text(text, encoding="utf-8")
        path.chmod(0o644)
    monkeypatch.setattr(
        runtime_lifecycle,
        "_runtime_identity",
        lambda _root: {
            "generation": "a" * 40,
            "manifest_digest": "sha256:" + "b" * 64,
            "consumer_pin": True,
        },
    )
    monkeypatch.setattr(runtime_lifecycle, "_d296_and_v2_accepted", lambda: True)
    monkeypatch.setattr(
        runtime_lifecycle, "_parse_health", lambda _root: (True, True, True)
    )
    monkeypatch.setattr(runtime_lifecycle, "_probe_gate_allowed", lambda _root: True)
    monkeypatch.setattr(
        runtime_lifecycle, "_observation_matches", lambda **_kwargs: False
    )

    result = runtime_lifecycle.verify(
        home=home,
        systemctl=lambda arguments: (
            {
                "LoadState": "not-found",
                "UnitFileState": "disabled",
                "ActiveState": "inactive",
                "Result": "success",
                "ExecMainStatus": "0",
            }
            if arguments[1].startswith("codex-master-")
            else {
                "LoadState": "loaded",
                "UnitFileState": "enabled",
                "ActiveState": "active",
                "Result": "success",
                "ExecMainStatus": "0",
            }
        ),
    )

    assert result["observed"] is False
    assert result["status"] == "runtime_lifecycle_red"


def test_verify_separates_green_runtime_from_blocked_product_authority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    units = home / ".config" / "systemd" / "user"
    units.mkdir(parents=True, mode=0o700)
    service = b"[Service]\nExecStart=/attested\n"
    timer = b"[Timer]\nOnCalendar=*-*-* 00,03,06,09,12,15,18,21:00:00 UTC\n"
    for name, content in (
        ("the-hive-hive-hourly-probe.service", service),
        ("the-hive-hive-hourly-probe.timer", timer),
    ):
        path = units / name
        path.write_bytes(content)
        path.chmod(0o644)
    identity = {
        "generation": "a" * 40,
        "manifest_digest": "sha256:" + "b" * 64,
        "consumer_pin": True,
    }
    monkeypatch.setattr(runtime_lifecycle, "_runtime_identity", lambda _root: identity)
    monkeypatch.setattr(
        runtime_lifecycle,
        "_attested_hourly_unit_bytes",
        lambda **_kwargs: (service, timer),
    )
    monkeypatch.setattr(runtime_lifecycle, "_d296_and_v2_accepted", lambda: True)
    monkeypatch.setattr(
        runtime_lifecycle, "_parse_health", lambda _root: (True, False, False)
    )
    monkeypatch.setattr(runtime_lifecycle, "_probe_gate_allowed", lambda _root: False)
    monkeypatch.setattr(
        runtime_lifecycle, "_observation_matches", lambda **_kwargs: True
    )

    def systemctl(arguments: tuple[str, ...]) -> dict[str, str]:
        if arguments[1].startswith("codex-master-"):
            return {
                "LoadState": "not-found",
                "UnitFileState": "disabled",
                "ActiveState": "inactive",
            }
        return {
            "LoadState": "loaded",
            "UnitFileState": "enabled",
            "ActiveState": "active",
        }

    result = runtime_lifecycle.verify(home=home, systemctl=systemctl)

    assert result["status"] == "runtime_lifecycle_green"
    assert result["error_code"] is None
    assert result["checks"]["health_v3_valid"] is True
    assert result["product_status"] == "blocked"
    assert result["product_checks"] == {
        "health_v3_green": False,
        "queen_alarm_cleared": False,
        "probe_gate_allowed": False,
    }


def test_observation_receipt_accepts_only_a_fresh_consistent_launcher_result(
    tmp_path: Path, monkeypatch
) -> None:
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    state_root = home / ".local" / "state" / "codex-master-mcp"
    state_root.mkdir(parents=True, mode=0o700)
    for directory in (home / ".local", home / ".local" / "state", state_root):
        directory.chmod(0o700)
    binding = runtime_lifecycle._ProbeObservationBinding(
        generation="a" * 40,
        manifest_digest="sha256:" + "b" * 64,
        launcher_sha256="c" * 64,
        launcher=home / ".local" / "libexec" / "codex_master_hive_hourly_probe.py",
        runtime_layout=object(),
    )
    identity = {
        "generation": binding.generation,
        "manifest_digest": binding.manifest_digest,
        "consumer_pin": True,
    }
    monkeypatch.setattr(runtime_lifecycle, "_runtime_identity", lambda _root: identity)
    monkeypatch.setattr(
        runtime_lifecycle, "_probe_observation_binding", lambda **_kwargs: binding
    )

    assert (
        runtime_lifecycle._observation_matches(
            home=home, state_root=state_root, identity=identity
        )
        is False
    )
    calls: list[tuple[str, ...]] = []

    def run_red(arguments, **_kwargs):
        calls.append(tuple(arguments))
        payload = json.loads(_canary_isolated_health())
        payload["checked_at"] = datetime.now(UTC).isoformat()
        health = state_root / "hive-hourly-health.json"
        health.write_text(json.dumps(payload), encoding="utf-8")
        health.chmod(0o600)
        return SimpleNamespace(returncode=1, stdout="{}", stderr="")

    monkeypatch.setattr(runtime_lifecycle, "run_bounded", run_red)
    runtime_lifecycle._observe_argumentless_installed_probe(home)

    assert calls == [(str(binding.launcher),)]
    assert (
        runtime_lifecycle._observation_matches(
            home=home, state_root=state_root, identity=identity
        )
        is True
    )

    def run_inconsistent(arguments, **_kwargs):
        calls.append(tuple(arguments))
        payload = json.loads(_canary_green_health())
        payload["checked_at"] = datetime.now(UTC).isoformat()
        health = state_root / "hive-hourly-health.json"
        health.write_text(json.dumps(payload), encoding="utf-8")
        health.chmod(0o600)
        return SimpleNamespace(returncode=1, stdout="{}", stderr="")

    monkeypatch.setattr(runtime_lifecycle, "run_bounded", run_inconsistent)
    with pytest.raises(
        runtime_lifecycle.RuntimeLifecycleError,
        match="^runtime_lifecycle_probe_result_invalid$",
    ):
        runtime_lifecycle._observe_argumentless_installed_probe(home)


def test_observation_does_not_write_a_receipt_when_the_bounded_launcher_fails(
    tmp_path: Path, monkeypatch
) -> None:
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    state_root = home / ".local" / "state" / "codex-master-mcp"
    state_root.mkdir(parents=True, mode=0o700)
    for directory in (home / ".local", home / ".local" / "state", state_root):
        directory.chmod(0o700)
    binding = runtime_lifecycle._ProbeObservationBinding(
        generation="a" * 40,
        manifest_digest="sha256:" + "b" * 64,
        launcher_sha256="c" * 64,
        launcher=home / ".local" / "libexec" / "codex_master_hive_hourly_probe.py",
        runtime_layout=object(),
    )
    monkeypatch.setattr(
        runtime_lifecycle,
        "_runtime_identity",
        lambda _root: {
            "generation": binding.generation,
            "manifest_digest": binding.manifest_digest,
            "consumer_pin": True,
        },
    )
    monkeypatch.setattr(
        runtime_lifecycle, "_probe_observation_binding", lambda **_kwargs: binding
    )
    monkeypatch.setattr(
        runtime_lifecycle,
        "run_bounded",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            runtime_lifecycle.BoundedProcessError("command_timeout")
        ),
    )

    try:
        runtime_lifecycle._observe_argumentless_installed_probe(home)
    except runtime_lifecycle.RuntimeLifecycleError as exc:
        assert str(exc) == "runtime_lifecycle_probe_observation_failed"
    else:
        raise AssertionError("a bounded launcher failure must fail closed")
    assert not (state_root / "runtime-lifecycle-probe-observation.json").exists()


def test_observation_receipt_remains_valid_for_its_unchanged_runtime_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    state_root = home / ".local" / "state" / "codex-master-mcp"
    state_root.mkdir(parents=True, mode=0o700)
    for directory in (home / ".local", home / ".local" / "state", state_root):
        directory.chmod(0o700)
    binding = runtime_lifecycle._ProbeObservationBinding(
        generation="a" * 40,
        manifest_digest="sha256:" + "b" * 64,
        launcher_sha256="c" * 64,
        launcher=home / ".local" / "libexec" / "codex_master_hive_hourly_probe.py",
        runtime_layout=object(),
    )
    identity = {
        "generation": binding.generation,
        "manifest_digest": binding.manifest_digest,
        "consumer_pin": True,
    }
    monkeypatch.setattr(
        runtime_lifecycle, "_probe_observation_binding", lambda **_kwargs: binding
    )
    receipt = state_root / "runtime-lifecycle-probe-observation.json"
    receipt.write_bytes(
        runtime_lifecycle._observation_payload(
            binding,
            observed_at=datetime(2025, 1, 1, tzinfo=UTC),
            returncode=1,
        )
    )
    receipt.chmod(0o600)

    assert (
        runtime_lifecycle._observation_matches(
            home=home, state_root=state_root, identity=identity
        )
        is True
    )


def test_status_and_verify_are_read_only_even_when_all_postconditions_are_red(
    tmp_path: Path,
) -> None:
    home = tmp_path / "home"
    units = home / ".config" / "systemd" / "user"
    state = home / ".local" / "state" / "codex-master-mcp"
    for directory in (
        home,
        home / ".config",
        home / ".config" / "systemd",
        units,
        home / ".local",
        home / ".local" / "state",
        state,
    ):
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        directory.chmod(0o700)
    for name in (
        "the-hive-hive-hourly-probe.service",
        "the-hive-hive-hourly-probe.timer",
    ):
        path = units / name
        path.write_text("[Unit]\n", encoding="utf-8")
        path.chmod(0o644)
    before = {path: _identity(path) for path in home.rglob("*") if path.is_file()}

    def systemctl(_arguments: tuple[str, ...]) -> dict[str, str]:
        return {
            "LoadState": "not-found",
            "UnitFileState": "disabled",
            "ActiveState": "inactive",
        }

    assert runtime_lifecycle.status(home=home, systemctl=systemctl)["status"] == (
        "runtime_lifecycle_red"
    )
    assert runtime_lifecycle.verify(home=home, systemctl=systemctl)["status"] == (
        "runtime_lifecycle_red"
    )
    assert {
        path: _identity(path) for path in home.rglob("*") if path.is_file()
    } == before


def test_installer_source_entry_rebind_rejects_before_runpy_loader(
    tmp_path: Path, monkeypatch
) -> None:
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    monkeypatch.setattr(
        runtime_lifecycle, "_source_tree_binding", lambda _repo: ("a" * 40, "b" * 64)
    )

    @runtime_lifecycle.contextmanager
    def broken_entry(_repository: Path):
        raise runtime_lifecycle.RuntimeLifecycleError(
            "runtime_lifecycle_source_entry_changed"
        )
        yield  # pragma: no cover

    monkeypatch.setattr(runtime_lifecycle, "_bound_installer_entry", broken_entry)
    monkeypatch.setattr(
        runtime_lifecycle,
        "runpy",
        type(
            "NoRunpy",
            (),
            {
                "run_path": staticmethod(
                    lambda _path: (_ for _ in ()).throw(AssertionError("must not load"))
                )
            },
        ),
    )

    try:
        runtime_lifecycle._install_attested_runtime(
            home,
            record_setup=lambda _stage: None,
            reserve_setup=lambda _path, _temporary, _digest: None,
            before_publish=lambda _stage, _layout, _outputs: None,
        )
    except runtime_lifecycle.RuntimeLifecycleError as exc:
        assert str(exc) == "runtime_lifecycle_source_entry_changed"
    else:
        raise AssertionError("a rebound installer entry must be rejected")


def test_internal_installer_without_v2_journal_stops_before_filesystem_effects(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    entry_calls: list[str] = []
    monkeypatch.setattr(
        runtime_lifecycle,
        "_source_tree_binding",
        lambda _repository: ("a" * 40, "b" * 64),
    )

    @runtime_lifecycle.contextmanager
    def entry(_repository: Path):
        entry_calls.append("opened")
        raise runtime_lifecycle.RuntimeLifecycleError("unexpected_entry_open")
        yield  # pragma: no cover

    monkeypatch.setattr(runtime_lifecycle, "_bound_installer_entry", entry)
    with pytest.raises(
        runtime_lifecycle.RuntimeLifecycleError,
        match="runtime_lifecycle_v2_journal_unavailable",
    ):
        runtime_lifecycle._install_attested_runtime(home)
    assert entry_calls == []
    assert list(home.iterdir()) == []


def test_legacy_executor_cannot_create_probe_lock_or_stage_without_v2_journal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bound, states = _bound_failure_fixture(tmp_path)
    home = bound.home
    monkeypatch.setattr(
        runtime_lifecycle,
        "_source_tree_binding",
        lambda _repository: ("a" * 40, "b" * 64),
    )
    monkeypatch.setattr(runtime_lifecycle, "_source_digest", lambda _path: "c" * 64)
    for unit in runtime_lifecycle._PRICING_UNITS:
        states[unit] = {
            "LoadState": "loaded",
            "UnitFileState": "disabled",
            "ActiveState": "inactive",
        }

    manager_mutations: list[tuple[str, ...]] = []

    def systemctl(arguments: tuple[str, ...]) -> dict[str, str]:
        if arguments[0] == "show":
            return states[arguments[1]]
        manager_mutations.append(arguments)
        return {}

    result = runtime_lifecycle._execute_cutover(home=home, systemctl=systemctl)

    assert result == {
        "status": "runtime_lifecycle_v2_journal_unavailable",
        "raw_output": "not_returned",
    }
    assert not (home / ".local/state/codex-master-mcp/.hive-hourly-probe.lock").exists()
    assert list((home / ".local/lib").glob(".the-hive-runtime.stage.*")) == []
    assert not (home / ".local/state/the-hive/hook-session-pins-v1").exists()
    assert manager_mutations == []


def test_postinstall_binding_rejects_syntactically_eight_term_malicious_units(
    tmp_path: Path, monkeypatch
) -> None:
    home = tmp_path / "home"
    units = home / ".config" / "systemd" / "user"
    units.mkdir(parents=True, mode=0o700)
    for directory in (home, home / ".config", home / ".config" / "systemd", units):
        directory.chmod(0o700)
    service = units / "the-hive-hive-hourly-probe.service"
    timer = units / "the-hive-hive-hourly-probe.timer"
    service.write_bytes(b"[Service]\nExecStart=/malicious\n")
    timer.write_bytes(b"[Timer]\nOnCalendar=*-*-* 00,03,06,09,12,15,18,21:00:00 UTC\n")
    service.chmod(0o644)
    timer.chmod(0o644)
    identity = {
        "generation": "a" * 40,
        "manifest_digest": "sha256:" + "b" * 64,
        "consumer_pin": True,
    }
    monkeypatch.setattr(runtime_lifecycle, "_runtime_identity", lambda _root: identity)
    monkeypatch.setattr(
        runtime_lifecycle,
        "_attested_hourly_unit_bytes",
        lambda **_kwargs: (
            b"[Service]\nExecStart=/attested\n",
            b"[Timer]\nOnCalendar=*-*-* 00,03,06,09,12,15,18,21:00:00 UTC\n",
        ),
    )

    with pytest.raises(
        runtime_lifecycle.RuntimeLifecycleError,
        match="runtime_lifecycle_postinstall_invalid",
    ):
        runtime_lifecycle._bind_post_install(home)


def test_restore_bound_state_restores_preexisting_runtime_pointer_units_and_receipt(
    tmp_path: Path,
) -> None:
    """A failed migration returns every preexisting private object byte-for-byte."""

    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    release = home / ".local" / "lib" / "the-hive-runtime"
    units = home / ".config" / "systemd" / "user"
    state = home / ".local" / "state" / "codex-master-mcp"
    launcher = home / ".local" / "libexec" / "codex_master_hive_hourly_probe.py"
    for directory in (
        home / ".local",
        home / ".local" / "lib",
        release,
        home / ".config",
        home / ".config" / "systemd",
        units,
        home / ".local" / "state",
        state,
        home / ".local" / "libexec",
    ):
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        directory.chmod(0o700)
    originals = {
        release / ".the-hive-release-pointers.json": (b'{"old":true}\n', 0o644),
        release / "the-hive-mcp": (b"old-mcp\n", 0o755),
        launcher: (b"old-launcher\n", 0o755),
        state / "runtime-lifecycle-probe-observation.json": (b'{"old":true}\n', 0o600),
        units / "the-hive-hive-hourly-probe.service": (b"old-new-service\n", 0o644),
        units / "the-hive-hive-hourly-probe.timer": (b"old-new-timer\n", 0o644),
        units / "codex-master-hive-hourly-probe.service": (
            b"old-legacy-service\n",
            0o644,
        ),
        units / "codex-master-hive-hourly-probe.timer": (b"old-legacy-timer\n", 0o644),
    }
    for path, (content, mode) in originals.items():
        path.write_bytes(content)
        path.chmod(mode)
    states = {
        "the-hive-hive-hourly-probe.service": {
            "LoadState": "loaded",
            "UnitFileState": "disabled",
            "ActiveState": "inactive",
        },
        "the-hive-hive-hourly-probe.timer": {
            "LoadState": "loaded",
            "UnitFileState": "disabled",
            "ActiveState": "inactive",
        },
        "codex-master-hive-hourly-probe.service": {
            "LoadState": "loaded",
            "UnitFileState": "disabled",
            "ActiveState": "active",
        },
        "codex-master-hive-hourly-probe.timer": {
            "LoadState": "loaded",
            "UnitFileState": "enabled",
            "ActiveState": "active",
        },
    }
    bound = runtime_lifecycle._BoundCutover(
        home=home,
        release_root=release,
        units=units,
        state_root=state,
        files=tuple(
            (path, content, mode) for path, (content, mode) in originals.items()
        ),
        source_digests=(),
        source_commit="a" * 40,
        generations_before=frozenset({"a" * 40}),
        legacy_present=True,
        states=tuple(states.items()),
    )
    for path, (_content, mode) in originals.items():
        path.write_bytes(b"new-state\n")
        path.chmod(mode)
    mutated = {path: _identity(path) for path in originals}
    calls: list[tuple[str, ...]] = []

    def systemctl(arguments: tuple[str, ...]) -> dict[str, str]:
        calls.append(arguments)
        if arguments[0] == "show":
            return states[arguments[1]]
        return {}

    assert runtime_lifecycle._restore_bound_state(bound, systemctl) is True
    assert {path: path.read_bytes() for path in originals} == {
        path: content for path, (content, _mode) in originals.items()
    }
    restored = {path: _identity(path) for path in originals}
    for path, (content, mode) in originals.items():
        device, inode, owner, restored_mode, nlink, bytes_value = restored[path]
        assert device == mutated[path][0]
        assert inode != mutated[path][1]
        assert owner == mutated[path][2]
        assert restored_mode == mode
        assert nlink == 1
        assert bytes_value == content
    assert ("daemon-reload",) in calls
    assert ("disable", "--now", "the-hive-hive-hourly-probe.timer") in calls
    assert ("start", "codex-master-hive-hourly-probe.service") in calls
    assert ("enable", "--now", "codex-master-hive-hourly-probe.timer") in calls


def test_restore_bound_state_removes_new_runtime_units_pointer_and_receipt(
    tmp_path: Path,
) -> None:
    """A first-cutover failure also restores the fully absent pre-cutover state."""

    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    release = home / ".local" / "lib" / "the-hive-runtime"
    units = home / ".config" / "systemd" / "user"
    state = home / ".local" / "state" / "codex-master-mcp"
    launcher = home / ".local" / "libexec" / "codex_master_hive_hourly_probe.py"
    for directory in (
        home / ".local",
        home / ".local" / "lib",
        release,
        home / ".config",
        home / ".config" / "systemd",
        units,
        home / ".local" / "state",
        state,
        home / ".local" / "libexec",
    ):
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        directory.chmod(0o700)
    paths = (
        release / ".the-hive-release-pointers.json",
        release / "the-hive-mcp",
        launcher,
        state / "runtime-lifecycle-probe-observation.json",
        units / "the-hive-hive-hourly-probe.service",
        units / "the-hive-hive-hourly-probe.timer",
        units / "codex-master-hive-hourly-probe.service",
        units / "codex-master-hive-hourly-probe.timer",
    )
    for path in paths:
        path.write_bytes(b"new-state\n")
        path.chmod(0o600 if path.name.endswith("observation.json") else 0o644)
    bound = runtime_lifecycle._BoundCutover(
        home=home,
        release_root=release,
        units=units,
        state_root=state,
        files=tuple(
            (path, None, 0o600 if path.name.endswith("observation.json") else 0o644)
            for path in paths
        ),
        source_digests=(),
        source_commit="a" * 40,
        generations_before=frozenset({"a" * 40}),
        legacy_present=False,
        states=tuple(
            (
                name,
                {
                    "LoadState": "not-found",
                    "UnitFileState": "disabled",
                    "ActiveState": "inactive",
                },
            )
            for name in (
                "the-hive-hive-hourly-probe.service",
                "the-hive-hive-hourly-probe.timer",
                "codex-master-hive-hourly-probe.service",
                "codex-master-hive-hourly-probe.timer",
            )
        ),
    )

    assert (
        runtime_lifecycle._restore_bound_state(
            bound,
            lambda arguments: (
                {
                    "LoadState": "not-found",
                    "UnitFileState": "disabled",
                    "ActiveState": "inactive",
                }
                if arguments[0] == "show"
                else {}
            ),
        )
        is True
    )
    assert all(not path.exists() for path in paths)


def test_restore_does_not_operate_on_units_bound_as_not_found(tmp_path: Path) -> None:
    bound, _states = _bound_failure_fixture(tmp_path)
    absent = {
        name: {
            "LoadState": "not-found",
            "UnitFileState": "disabled",
            "ActiveState": "inactive",
        }
        for name in (
            "the-hive-hive-hourly-probe.service",
            "the-hive-hive-hourly-probe.timer",
            "codex-master-hive-hourly-probe.service",
            "codex-master-hive-hourly-probe.timer",
        )
    }
    bound = runtime_lifecycle.replace(bound, states=tuple(absent.items()))
    calls: list[tuple[str, ...]] = []

    def systemctl(arguments: tuple[str, ...]) -> dict[str, str]:
        calls.append(arguments)
        return absent[arguments[1]] if arguments[0] == "show" else {}

    assert runtime_lifecycle._restore_bound_state(bound, systemctl) is True
    assert calls == [
        ("daemon-reload",),
        *(
            (
                "show",
                name,
                "--property=LoadState,UnitFileState,ActiveState,Result,ExecMainStatus",
            )
            for name in absent
        ),
    ]


def test_restore_bound_failed_oneshot_resets_the_manager_failed_state_before_verify(
    tmp_path: Path,
) -> None:
    """A quiescent failed oneshot still receives the full safe inverse.

    Stop remains the central quiescing guard even when the manager has already
    recorded failure; ``reset-failed`` then clears that record before the exact
    quiescent verification. Accepting ``failed`` would hide a broken restore.
    """

    bound, states = _bound_failure_fixture(tmp_path)
    service = "the-hive-hive-hourly-probe.service"
    states[service] = {
        "LoadState": "loaded",
        "UnitFileState": "static",
        "ActiveState": "failed",
    }
    bound = runtime_lifecycle.replace(bound, states=tuple(states.items()))
    calls: list[tuple[str, ...]] = []

    def systemctl(arguments: tuple[str, ...]) -> dict[str, str]:
        calls.append(arguments)
        if arguments == ("reset-failed", service):
            states[service] = {
                "LoadState": "loaded",
                "UnitFileState": "static",
                "ActiveState": "inactive",
            }
            return {}
        if arguments[0] == "show":
            return states[arguments[1]]
        return {}

    assert runtime_lifecycle._restore_bound_state(bound, systemctl) is True
    assert calls.index(("stop", service)) < calls.index(("reset-failed", service))
    assert states[service]["ActiveState"] == "inactive"


def test_restore_bound_inactive_oneshot_resets_a_cutover_created_failed_record(
    tmp_path: Path,
) -> None:
    """Stop alone cannot restore an inactive oneshot after a failed cutover."""

    bound, states = _bound_failure_fixture(tmp_path)
    service = "the-hive-hive-hourly-probe.service"
    states[service] = {
        "LoadState": "loaded",
        "UnitFileState": "static",
        "ActiveState": "inactive",
    }
    bound = runtime_lifecycle.replace(bound, states=tuple(states.items()))
    # This is the manager state left by the failed candidate service. A stop
    # operation is deliberately a no-op for the failed record; only
    # reset-failed restores the exact inactive rollback target.
    states[service] = {
        "LoadState": "loaded",
        "UnitFileState": "static",
        "ActiveState": "failed",
    }
    calls: list[tuple[str, ...]] = []

    def systemctl(arguments: tuple[str, ...]) -> dict[str, str]:
        calls.append(arguments)
        if arguments == ("stop", service):
            return {}
        if arguments == ("reset-failed", service):
            states[service] = {
                "LoadState": "loaded",
                "UnitFileState": "static",
                "ActiveState": "inactive",
            }
            return {}
        if arguments[0] == "show":
            return states[arguments[1]]
        return {}

    result = runtime_lifecycle._restore_bound_state_result(bound, systemctl)

    assert result == runtime_lifecycle._RollbackResult(True, "complete", "none")
    stop = ("stop", service)
    reset = ("reset-failed", service)
    show = (
        "show",
        service,
        "--property=LoadState,UnitFileState,ActiveState,Result,ExecMainStatus",
    )
    stop_index = calls.index(stop)
    probe_index = calls.index(show, stop_index + 1)
    reset_index = calls.index(reset, probe_index + 1)
    assert stop_index < probe_index < reset_index
    assert show in calls[reset_index + 1 :]
    assert states[service] == {
        "LoadState": "loaded",
        "UnitFileState": "static",
        "ActiveState": "inactive",
    }


def test_restore_bound_failed_oneshot_skips_reset_after_stop_quiesces_service(
    tmp_path: Path,
) -> None:
    """A failed pre-cutover oneshot cannot leave a cutover-started service active."""

    bound, states = _bound_failure_fixture(tmp_path)
    service = "the-hive-hive-hourly-probe.service"
    states[service] = {
        "LoadState": "loaded",
        "UnitFileState": "static",
        "ActiveState": "failed",
    }
    bound = runtime_lifecycle.replace(bound, states=tuple(states.items()))
    states[service] = {
        "LoadState": "loaded",
        "UnitFileState": "static",
        "ActiveState": "active",
    }
    calls: list[tuple[str, ...]] = []

    def systemctl(arguments: tuple[str, ...]) -> dict[str, str]:
        calls.append(arguments)
        if arguments == ("stop", service):
            states[service]["ActiveState"] = "inactive"
            return {}
        if arguments == ("reset-failed", service):
            return {}
        if arguments[0] == "show":
            return states[arguments[1]]
        return {}

    assert runtime_lifecycle._restore_bound_state(bound, systemctl) is True
    stop = ("stop", service)
    show = (
        "show",
        service,
        "--property=LoadState,UnitFileState,ActiveState,Result,ExecMainStatus",
    )
    assert calls.index(stop) < calls.index(show)
    assert ("reset-failed", service) not in calls
    assert states[service]["ActiveState"] == "inactive"


def test_restore_bound_inactive_service_skips_absent_manager_failure_record(
    tmp_path: Path,
) -> None:
    """Valid inactive Legacy units must not receive failing reset-failed calls."""

    bound, states = _bound_failure_fixture(tmp_path)
    service = "codex-master-hive-hourly-probe.service"
    states[service] = {
        "LoadState": "loaded",
        "UnitFileState": "static",
        "ActiveState": "inactive",
    }
    bound = runtime_lifecycle.replace(bound, states=tuple(states.items()))
    calls: list[tuple[str, ...]] = []

    def systemctl(arguments: tuple[str, ...]) -> dict[str, str]:
        calls.append(arguments)
        if arguments == ("reset-failed", service):
            raise runtime_lifecycle.RuntimeLifecycleError("unit-not-loaded")
        if arguments[0] == "show":
            return states[arguments[1]]
        return {}

    assert runtime_lifecycle._restore_bound_state(bound, systemctl) is True
    assert ("stop", service) in calls
    assert ("reset-failed", service) not in calls


@pytest.mark.parametrize(
    ("service", "phase", "failing_operation"),
    (
        (
            "the-hive-hive-hourly-probe.service",
            "new_service_action",
            ("stop", "the-hive-hive-hourly-probe.service"),
        ),
        (
            "the-hive-hive-hourly-probe.service",
            "new_service_action",
            ("reset-failed", "the-hive-hive-hourly-probe.service"),
        ),
        (
            "codex-master-hive-hourly-probe.service",
            "legacy_service_action",
            ("stop", "codex-master-hive-hourly-probe.service"),
        ),
        (
            "codex-master-hive-hourly-probe.service",
            "legacy_service_action",
            ("reset-failed", "codex-master-hive-hourly-probe.service"),
        ),
    ),
)
def test_restore_bound_failed_service_sequence_reports_each_failed_suboperation(
    tmp_path: Path, service: str, phase: str, failing_operation: tuple[str, ...]
) -> None:
    """Each failed-service inverse operation keeps its unit's fixed phase code."""

    bound, states = _bound_failure_fixture(tmp_path)
    states[service] = {
        "LoadState": "loaded",
        "UnitFileState": "static",
        "ActiveState": "failed",
    }
    bound = runtime_lifecycle.replace(bound, states=tuple(states.items()))

    def systemctl(arguments: tuple[str, ...]) -> dict[str, str]:
        if arguments == failing_operation:
            raise runtime_lifecycle.RuntimeLifecycleError("untrusted-manager-detail")
        if arguments == ("stop", service):
            if failing_operation[0] != "reset-failed":
                states[service]["ActiveState"] = "inactive"
            return {}
        if arguments == ("reset-failed", service):
            return {}
        if arguments[0] == "show":
            return states[arguments[1]]
        return {}

    result = runtime_lifecycle._restore_bound_state_result(bound, systemctl)

    assert result == runtime_lifecycle._RollbackResult(
        False, phase, "manager_action_failed"
    )


@pytest.mark.parametrize(
    "failing_operation",
    (
        ("stop", "the-hive-hive-hourly-probe.service"),
        ("reset-failed", "the-hive-hive-hourly-probe.service"),
    ),
)
def test_restore_bound_inactive_service_keeps_its_action_phase_on_failure(
    tmp_path: Path, failing_operation: tuple[str, str]
) -> None:
    """New inactive-service normalization retains the service action phase."""

    bound, states = _bound_failure_fixture(tmp_path)
    service = "the-hive-hive-hourly-probe.service"
    states[service] = {
        "LoadState": "loaded",
        "UnitFileState": "static",
        "ActiveState": "inactive",
    }
    bound = runtime_lifecycle.replace(bound, states=tuple(states.items()))
    states[service] = {
        "LoadState": "loaded",
        "UnitFileState": "static",
        "ActiveState": "failed",
    }

    def systemctl(arguments: tuple[str, ...]) -> dict[str, str]:
        if arguments == failing_operation:
            raise runtime_lifecycle.RuntimeLifecycleError("untrusted-manager-detail")
        if arguments == ("reset-failed", service):
            states[service] = {
                "LoadState": "loaded",
                "UnitFileState": "static",
                "ActiveState": "inactive",
            }
            return {}
        if arguments[0] == "show":
            return states[arguments[1]]
        return {}

    assert runtime_lifecycle._restore_bound_state_result(
        bound, systemctl
    ) == runtime_lifecycle._RollbackResult(
        False, "new_service_action", "manager_action_failed"
    )


@pytest.mark.parametrize(
    ("failing_call", "phase"),
    (
        (("daemon-reload",), "restore_daemon_reload"),
        (("disable", "--now", "the-hive-hive-hourly-probe.timer"), "new_timer_action"),
        (("stop", "the-hive-hive-hourly-probe.service"), "new_service_action"),
        (
            ("enable", "--now", "codex-master-hive-hourly-probe.timer"),
            "legacy_timer_action",
        ),
        (("start", "codex-master-hive-hourly-probe.service"), "legacy_service_action"),
    ),
)
def test_restore_bound_state_result_reports_each_manager_action_phase(
    tmp_path: Path, failing_call: tuple[str, ...], phase: str
) -> None:
    """Rollback diagnostics identify the bounded manager operation that failed."""

    bound, states = _bound_failure_fixture(tmp_path)

    def systemctl(arguments: tuple[str, ...]) -> dict[str, str]:
        if arguments == failing_call:
            raise runtime_lifecycle.RuntimeLifecycleError("untrusted-manager-detail")
        if arguments[0] == "show":
            return states[arguments[1]]
        return {}

    result = runtime_lifecycle._restore_bound_state_result(bound, systemctl)

    assert result == runtime_lifecycle._RollbackResult(
        False, phase, "manager_action_failed"
    )
    assert "untrusted-manager-detail" not in (result.phase, result.error_code)


def test_restore_bound_state_result_reports_file_and_generation_phases(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """File and generation failures remain distinct fixed rollback outcomes."""

    bound, states = _bound_failure_fixture(tmp_path)
    path = bound.files[0][0]
    path.unlink()
    path.symlink_to(tmp_path / "untrusted")

    file_result = runtime_lifecycle._restore_bound_state_result(
        bound, lambda arguments: states[arguments[1]] if arguments[0] == "show" else {}
    )

    assert file_result == runtime_lifecycle._RollbackResult(
        False, "file_restore", "file_restore_failed"
    )

    generation_root = tmp_path / "generation"
    generation_root.mkdir()
    bound, states = _bound_failure_fixture(generation_root)
    monkeypatch.setattr(
        runtime_lifecycle,
        "_discard_new_generation",
        lambda _bound: (_ for _ in ()).throw(
            runtime_lifecycle.RuntimeLifecycleError("untrusted-generation-detail")
        ),
    )
    generation_result = runtime_lifecycle._restore_bound_state_result(
        bound, lambda arguments: states[arguments[1]] if arguments[0] == "show" else {}
    )

    assert generation_result == runtime_lifecycle._RollbackResult(
        False, "generation_discard", "generation_discard_failed"
    )


@pytest.mark.parametrize(
    "unit",
    (
        "the-hive-hive-hourly-probe.timer",
        "the-hive-hive-hourly-probe.service",
        "codex-master-hive-hourly-probe.timer",
        "codex-master-hive-hourly-probe.service",
    ),
)
def test_restore_bound_state_result_reports_each_unit_verification_mismatch(
    tmp_path: Path, unit: str
) -> None:
    """The public-safe phase identifies exactly which restored unit mismatched."""

    bound, states = _bound_failure_fixture(tmp_path)

    def systemctl(arguments: tuple[str, ...]) -> dict[str, str]:
        if arguments[0] != "show":
            return {}
        actual = dict(states[arguments[1]])
        if arguments[1] == unit:
            actual["ActiveState"] = (
                "inactive" if actual["ActiveState"] != "inactive" else "failed"
            )
        return actual

    result = runtime_lifecycle._restore_bound_state_result(bound, systemctl)

    assert result == runtime_lifecycle._RollbackResult(
        False,
        {
            "the-hive-hive-hourly-probe.timer": "new_timer_verify",
            "the-hive-hive-hourly-probe.service": "new_service_verify",
            "codex-master-hive-hourly-probe.timer": "legacy_timer_verify",
            "codex-master-hive-hourly-probe.service": "legacy_service_verify",
        }[unit],
        "unit_verify_mismatch",
    )


def test_rollback_failure_result_rejects_unbounded_telemetry() -> None:
    """No exception text can reach the public cutover result through telemetry."""

    result = runtime_lifecycle._rollback_failure_result(
        status="runtime_lifecycle_rollback_failed",
        rollback=runtime_lifecycle._RollbackResult(
            False, "untrusted-phase", "secret-or-exception-text"
        ),
    )

    assert result == {
        "status": "runtime_lifecycle_rollback_failed",
        "raw_output": "not_returned",
        "rollback_phase": "telemetry_invalid",
        "rollback_error": "telemetry_invalid",
    }


def test_cutover_mutation_failure_result_rejects_unbounded_telemetry() -> None:
    """Unexpected carrier data fails closed without publishing exception text."""

    result = runtime_lifecycle._cutover_mutation_failure_result(
        runtime_lifecycle._CutoverMutationError(
            phase="untrusted-phase",
            error=runtime_lifecycle.RuntimeLifecycleError("untrusted-error-detail"),
        )
    )

    assert result == {
        "status": "runtime_lifecycle_systemd_failed",
        "raw_output": "not_returned",
        "failure_phase": "telemetry_invalid",
        "failure_error": "telemetry_invalid",
    }
    assert "untrusted" not in repr(result)


def test_cutover_mutation_failure_result_rejects_unknown_status_for_valid_phase() -> (
    None
):
    """A known phase cannot make an unknown underlying failure telemetricly valid."""

    result = runtime_lifecycle._cutover_mutation_failure_result(
        runtime_lifecycle._CutoverMutationError(
            phase="new_timer_enable",
            error=runtime_lifecycle.RuntimeLifecycleError("untrusted-error-detail"),
        )
    )

    assert result == {
        "status": "runtime_lifecycle_systemd_failed",
        "raw_output": "not_returned",
        "failure_phase": "telemetry_invalid",
        "failure_error": "telemetry_invalid",
    }
    assert "untrusted" not in repr(result)


@pytest.mark.parametrize(
    "status",
    (
        "runtime_lifecycle_systemd_failed",
        "runtime_lifecycle_systemd_invalid",
        "runtime_lifecycle_systemd_unavailable",
    ),
)
def test_cutover_mutation_failure_result_accepts_each_whitelisted_status(
    status: str,
) -> None:
    """Every documented manager status keeps the bounded primary phase."""

    result = runtime_lifecycle._cutover_mutation_failure_result(
        runtime_lifecycle._CutoverMutationError(
            phase="new_timer_enable",
            error=runtime_lifecycle.RuntimeLifecycleError(status),
        )
    )

    assert result == {
        "status": status,
        "raw_output": "not_returned",
        "failure_phase": "new_timer_enable",
        "failure_error": "systemd_mutation_failed",
    }


def test_generation_discard_accepts_installer_self_cleanup(tmp_path: Path) -> None:
    release_root = tmp_path / "the-hive-runtime"
    (release_root / "generations").mkdir(mode=0o700, parents=True)
    bound = SimpleNamespace(
        source_commit="b" * 40,
        generations_before=frozenset({"a" * 40}),
        release_root=release_root,
    )

    runtime_lifecycle._discard_new_generation(bound)


def _d332_digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _d332_blob(kind: str, raw: bytes = b"evidence") -> dict[str, object]:
    return {
        "kind": kind,
        "format": "application/octet-stream",
        "bytes_b64": base64.b64encode(raw).decode("ascii"),
        "sha256": _d332_digest(raw),
        "size": len(raw),
    }


def _d332_snapshot(
    name: str, raw: bytes | None = None, *, present: bool = True
) -> dict[str, object]:
    if not present:
        return {
            "name": name,
            "path": f"/precutover/{name}",
            "present": False,
            "bytes_b64": None,
            "sha256": None,
            "dev": None,
            "ino": None,
            "uid": None,
            "gid": None,
            "mode": None,
            "nlink": None,
            "size": None,
        }
    assert raw is not None
    return {
        "name": name,
        "path": f"/precutover/{name}",
        "present": True,
        "bytes_b64": base64.b64encode(raw).decode("ascii"),
        "sha256": _d332_digest(raw),
        "dev": 1,
        "ino": 2,
        "uid": 3,
        "gid": 4,
        "mode": 0o644,
        "nlink": 1,
        "size": len(raw),
    }


def _d332_step(
    *,
    index: int = 0,
    status: str = "VERIFIED",
    inverse: bool = True,
) -> dict[str, object]:
    preconditions = _d332_blob("preconditions")
    verified = status in {"VERIFIED", "INVERSE_INTENT", "INVERSE_VERIFIED"}
    started = status in {
        "EFFECT_STARTED",
        "VERIFIED",
        "INVERSE_INTENT",
        "INVERSE_VERIFIED",
    }
    inverse_phase = status in {"INVERSE_INTENT", "INVERSE_VERIFIED"}
    return {
        "index": index,
        "operation": f"operation-{index}",
        "status": status,
        "preconditions": preconditions,
        "intent_unix_ms": 11,
        "effect_started_unix_ms": 12 if started else None,
        "effect_ended_unix_ms": 13 if verified else None,
        "readback": _d332_blob("readback") if verified else None,
        "file_fsync": True if verified else None,
        "parent_fsync": True if verified else None,
        "adapter_receipt": _d332_blob("receipt") if verified else None,
        "inverse": _d332_blob("inverse") if inverse or inverse_phase else None,
    }


def _d332_history(state: str) -> list[dict[str, object]]:
    states = (
        "PREFLIGHTED",
        "ROOT_ABI_VERIFIED",
        "NATIVE_PREPARED_DISABLED",
        "NATIVE_TRUST_VERIFIED_DISABLED",
        "NATIVE_COMMITTED_DISABLED",
        "USER_CUTOVER_IN_PROGRESS",
        "USER_CUTOVER_VERIFIED",
    )
    previous = "ABSENT"
    history: list[dict[str, object]] = []
    for sequence, current in enumerate(states, start=1):
        history.append(
            {
                "sequence": sequence,
                "from": previous,
                "to": current,
                "at_unix_ms": 100 + sequence,
                "reason_code": "transition",
            }
        )
        previous = current
        if current == state:
            return history
    raise AssertionError(f"unsupported test state: {state}")


def _d333_lock_trace(state: str, sequence: int) -> list[dict[str, object]]:
    if state == "ABSENT":
        return []
    trace: list[dict[str, object]] = [
        {
            "event": "ACQUIRE",
            "lock": "D324-Journallock",
            "state": "PREFLIGHTED",
            "sequence": 1,
        }
    ]
    if state in {"ROLLED_BACK", "BLOCKED", "LIVE_GRANTED"}:
        trace.append(
            {
                "event": "RELEASE",
                "lock": "D324-Journallock",
                "state": state,
                "sequence": sequence,
            }
        )
    return trace


def _d332_payload(
    *,
    state: str = "ABSENT",
    sequence: int = 0,
    recovery_count: int = 0,
    steps: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    snapshots = {
        name: _d332_snapshot(
            name,
            None if name == "legacy_launcher" else f"old-{name}".encode("ascii"),
            present=name != "legacy_launcher",
        )
        for name in (
            "pointer",
            "mcp_launcher",
            "user_launcher",
            "legacy_launcher",
            "service",
            "timer",
            "config_binding",
        )
    }
    postcutover = {
        name: _d332_snapshot(name, f"new-{name}".encode("ascii"), present=True)
        for name in (
            "pointer",
            "mcp_launcher",
            "user_launcher",
            "legacy_launcher",
            "service",
            "timer",
            "config_binding",
        )
    }
    history = [] if state == "ABSENT" else _d332_history(state)
    return {
        "schema": "D320CutoverJournalV1",
        "journal_id": "journal-1",
        "sequence": sequence,
        "state": state,
        "controller": "controller-1",
        "created_unix_ms": 100,
        "updated_unix_ms": 100 + sequence,
        "recovery_count": recovery_count,
        "source": {
            "commit": "a" * 40,
            "tree": "b" * 40,
            "plan_sha256": "c" * 64,
            "decision_sha256": "d" * 64,
            "generation": "generation-1",
        },
        "digests": {
            "runtime_manifest_sha256": "e" * 64,
            "descriptor_sha256": "f" * 64,
            "root_install_plan_sha256": "1" * 64,
            "dispatch_allowlist_sha256": "2" * 64,
            "hooks": {
                "native_bee_event": "3" * 64,
                "native_spawn_admission": "4" * 64,
            },
        },
        "abi": {
            "version": 1,
            "expected_mode": 0o755,
            "root_receipt": {
                "dev": 1,
                "ino": 2,
                "uid": 0,
                "gid": 0,
                "mode": 0o755,
                "nlink": 1,
                "size": 3,
                "sha256": "5" * 64,
                "parent_chain": [
                    {
                        "path": "/usr",
                        "dev": 1,
                        "ino": 2,
                        "uid": 0,
                        "gid": 0,
                        "mode": 0o755,
                        "nlink": 2,
                    }
                ],
                "file_fsync": True,
                "parent_fsync": True,
            },
        },
        "native": {
            "marketplace": _d332_blob("marketplace"),
            "plugin": _d332_blob("plugin"),
            "cache": _d332_blob("cache"),
            "hook_definition": _d332_blob("hook_definition"),
            "trust": _d332_blob("trust"),
            "adapter_version": "adapter-1",
            "request_id": "request-1",
            "receipt_sha256": "6" * 64,
            "disabled": True,
            "inverse": _d332_blob("native_inverse"),
        },
        "precutover": {**snapshots, "unit_status": _d332_blob("unit_status")},
        "postcutover": {
            **postcutover,
            "unit_status": _d332_blob("unit_status", b"new-unit-status"),
        },
        "pins": {"current": ["generation-1"], "previous": [], "retained": []},
        "history": history,
        "steps": [] if steps is None else steps,
        "lock_trace": _d333_lock_trace(state, sequence),
    }


def _d332_new_snapshots(
    payload: dict[str, object],
) -> dict[str, object]:
    postcutover = payload["postcutover"]
    assert isinstance(postcutover, dict)
    result: dict[str, object] = {}
    for name in (
        "pointer",
        "mcp_launcher",
        "user_launcher",
        "legacy_launcher",
        "service",
        "timer",
        "config_binding",
    ):
        result[name] = runtime_lifecycle.ByteSnapshotV1.from_mapping(postcutover[name])
    result["unit_status"] = runtime_lifecycle.EvidenceBlobV1.from_mapping(
        postcutover["unit_status"]
    )
    return result


def _d332_old_snapshots(
    payload: dict[str, object],
) -> dict[str, object]:
    precutover = payload["precutover"]
    assert isinstance(precutover, dict)
    result: dict[str, object] = {
        name: runtime_lifecycle.ByteSnapshotV1.from_mapping(precutover[name])
        for name in (
            "pointer",
            "mcp_launcher",
            "user_launcher",
            "legacy_launcher",
            "service",
            "timer",
            "config_binding",
        )
    }
    result["unit_status"] = runtime_lifecycle.EvidenceBlobV1.from_mapping(
        precutover["unit_status"]
    )
    return result


def test_d332_evidence_blob_and_snapshot_are_purely_validated() -> None:
    blob = _d332_blob("blob", b"bytes")
    snapshot = _d332_snapshot("pointer", b"pointer")

    assert runtime_lifecycle.EvidenceBlobV1.from_mapping(blob).to_mapping() == blob
    assert (
        runtime_lifecycle.ByteSnapshotV1.from_mapping(snapshot).to_mapping() == snapshot
    )

    malformed = copy.deepcopy(blob)
    malformed["bytes_b64"] = "not-base64"
    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.EvidenceBlobV1.from_mapping(malformed)

    absent = _d332_snapshot("legacy_launcher", present=False)
    assert runtime_lifecycle.ByteSnapshotV1.from_mapping(absent).present is False
    absent["size"] = 0
    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.ByteSnapshotV1.from_mapping(absent)


def test_d332_transition_and_step_require_exact_phase_data() -> None:
    transition = {
        "sequence": 1,
        "from": "ABSENT",
        "to": "PREFLIGHTED",
        "at_unix_ms": 101,
        "reason_code": "preflight",
    }
    assert (
        runtime_lifecycle.TransitionV1.from_mapping(transition).to_mapping()
        == transition
    )

    verified = _d332_step()
    assert runtime_lifecycle.StepV1.from_mapping(verified).to_mapping() == verified

    partial = _d332_step(status="EFFECT_STARTED")
    partial["effect_ended_unix_ms"] = 13
    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.StepV1.from_mapping(partial)

    inverse_intent = _d332_step(status="INVERSE_INTENT", inverse=True)
    assert (
        runtime_lifecycle.StepV1.from_mapping(inverse_intent).status == "INVERSE_INTENT"
    )


def test_d332_journal_emits_exact_canonical_envelope_and_round_trips() -> None:
    payload = _d332_payload()
    journal = runtime_lifecycle.D320CutoverJournalV1.from_payload(payload)
    raw = journal.to_bytes()

    assert raw.endswith(b"\n")
    assert raw.count(b"\n") == 1
    assert raw == (
        b'{"content_sha256":"'
        + hashlib.sha256(journal.payload_bytes).hexdigest().encode("ascii")
        + b'","payload":'
        + journal.payload_bytes
        + b"}\n"
    )
    assert runtime_lifecycle.D320CutoverJournalV1.from_bytes(raw).payload == payload


@pytest.mark.parametrize(
    "mutation",
    (
        lambda payload: payload.__setitem__("unknown", None),
        lambda payload: payload.__setitem__("sequence", True),
        lambda payload: payload.__setitem__("sequence", 1.5),
        lambda payload: payload["precutover"]["pointer"].__setitem__(
            "path", "/not/nfc-e\u0301"
        ),
    ),
)
def test_d332_journal_rejects_unknown_noncanonical_and_noninteger_payloads(
    mutation,
) -> None:
    payload = _d332_payload()
    mutation(payload)

    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.D320CutoverJournalV1.from_payload(payload)


def test_d332_journal_rejects_duplicate_digest_and_size_violations() -> None:
    payload = _d332_payload()
    journal = runtime_lifecycle.D320CutoverJournalV1.from_payload(payload)
    duplicate = (
        b'{"content_sha256":"'
        + hashlib.sha256(journal.payload_bytes).hexdigest().encode("ascii")
        + b'","content_sha256":"'
        + hashlib.sha256(journal.payload_bytes).hexdigest().encode("ascii")
        + b'","payload":'
        + journal.payload_bytes
        + b"}\n"
    )
    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.D320CutoverJournalV1.from_bytes(duplicate)

    tampered = bytearray(journal.to_bytes())
    tampered[-2] = ord(" ")
    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.D320CutoverJournalV1.from_bytes(bytes(tampered))

    oversized = b"x" * (4_194_304 + 1)
    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.D320CutoverJournalV1.from_bytes(oversized)

    aggregate = _d332_payload()
    huge = b"x" * 1_048_576
    for name in ("marketplace", "plugin", "cache", "hook_definition"):
        aggregate["native"][name] = _d332_blob(name, huge)
    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.D320CutoverJournalV1.from_payload(aggregate)


def test_d332_history_graph_sequence_and_recovery_counter_are_monotone() -> None:
    previous = runtime_lifecycle.D320CutoverJournalV1.from_payload(_d332_payload())

    successor_payload = _d332_payload(state="PREFLIGHTED", sequence=1)
    successor_payload["updated_unix_ms"] = 101
    successor = runtime_lifecycle.D320CutoverJournalV1.from_payload(successor_payload)
    runtime_lifecycle.validate_d320_journal_successor(previous, successor)

    wrong_sequence = runtime_lifecycle.D320CutoverJournalV1.from_payload(
        _d332_payload(state="PREFLIGHTED", sequence=2)
    )
    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.validate_d320_journal_successor(previous, wrong_sequence)

    recovery = runtime_lifecycle.D320CutoverJournalV1.from_payload(
        _d332_payload(sequence=1, recovery_count=1)
    )
    runtime_lifecycle.validate_d320_journal_successor(
        previous, recovery, recovery_entry=True
    )
    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.validate_d320_journal_successor(previous, recovery)


def test_d332_lock_order_rejects_inversions_and_multiple_instances() -> None:
    trace = _d333_complete_lock_trace()
    history = _d332_history_for_states(("PREFLIGHTED", "ABORTING", "ROLLED_BACK"))
    runtime_lifecycle.validate_d324_lock_order(
        trace, state="ROLLED_BACK", sequence=3, history=history
    )

    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.validate_d324_lock_order(
            list(reversed(trace)), state="ROLLED_BACK", sequence=3, history=history
        )
    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.validate_d324_lock_order(
            trace + [trace[-1]], state="ROLLED_BACK", sequence=3, history=history
        )


def test_d337_public_primitive_boundaries_reject_overridable_subtypes() -> None:
    class ExplodingText(str):
        def encode(self, *args: object, **kwargs: object) -> bytes:
            raise RuntimeError("unexpected text encode")

    class ExplodingInteger(int):
        def __lt__(self, other: object) -> bool:
            raise RuntimeError("unexpected integer comparison")

    with pytest.raises(
        runtime_lifecycle.D320CutoverJournalError, match="d320_text_invalid"
    ):
        runtime_lifecycle.validate_d324_lock_order(
            [], state=ExplodingText("ABSENT"), sequence=0, history=[]
        )
    with pytest.raises(
        runtime_lifecycle.D320CutoverJournalError, match="d320_integer_required"
    ):
        runtime_lifecycle.validate_d324_lock_order(
            [], state="ABSENT", sequence=ExplodingInteger(0), history=[]
        )


def test_d337_successor_revalidates_carriers_and_exact_recovery_entry() -> None:
    previous = runtime_lifecycle.D320CutoverJournalV1.from_payload(_d332_payload())
    successor_payload = _d332_payload(state="PREFLIGHTED", sequence=1)
    successor_payload["updated_unix_ms"] = 101
    successor = runtime_lifecycle.D320CutoverJournalV1.from_payload(successor_payload)

    class ExplodingJournal(runtime_lifecycle.D320CutoverJournalV1):
        def to_bytes(self) -> bytes:
            raise RuntimeError("unexpected journal serialization")

    class ExplodingRecoveryEntry:
        def __bool__(self) -> bool:
            raise RuntimeError("unexpected recovery truthiness")

    runtime_lifecycle.validate_d320_journal_successor(
        ExplodingJournal(previous.payload_bytes), successor
    )
    with pytest.raises(
        runtime_lifecycle.D320CutoverJournalError,
        match="d320_recovery_entry_invalid",
    ):
        runtime_lifecycle.validate_d320_journal_successor(
            previous,
            successor,
            recovery_entry=ExplodingRecoveryEntry(),  # type: ignore[arg-type]
        )


def test_d338_journal_factories_reject_subclass_dispatch() -> None:
    payload = _d332_payload()
    expected = runtime_lifecycle.D320CutoverJournalV1.from_payload(payload)

    class ExplodingJournal(runtime_lifecycle.D320CutoverJournalV1):
        def to_bytes(self) -> bytes:
            raise RuntimeError("unexpected journal serialization")

    with pytest.raises(
        runtime_lifecycle.D320CutoverJournalError,
        match="d320_journal_factory_type_invalid",
    ):
        ExplodingJournal.from_payload(payload)
    with pytest.raises(
        runtime_lifecycle.D320CutoverJournalError,
        match="d320_journal_factory_type_invalid",
    ):
        ExplodingJournal.from_bytes(expected.to_bytes())

    assert runtime_lifecycle.D320CutoverJournalV1.from_payload(payload).to_bytes() == (
        expected.to_bytes()
    )
    assert (
        runtime_lifecycle.D320CutoverJournalV1.from_bytes(
            expected.to_bytes()
        ).payload_bytes
        == expected.payload_bytes
    )


def test_d338_carrier_base_views_ignore_subclass_accessor_overrides() -> None:
    evidence_mapping = _d332_blob("evidence")
    snapshot_mapping = _d332_snapshot("pointer", b"pointer")
    transition_mapping = {
        "sequence": 1,
        "from": "ABSENT",
        "to": "PREFLIGHTED",
        "at_unix_ms": 1,
        "reason_code": "preflight",
    }
    step_mapping = _d332_step(status="INTENT", inverse=False)
    journal_mapping = _d332_payload()

    class ExplodingEvidence(runtime_lifecycle.EvidenceBlobV1):
        def to_mapping(self) -> dict[str, object]:
            raise RuntimeError("unexpected evidence mapping")

    class ExplodingSnapshot(runtime_lifecycle.ByteSnapshotV1):
        def to_mapping(self) -> dict[str, object]:
            raise RuntimeError("unexpected snapshot mapping")

    class ExplodingTransition(runtime_lifecycle.TransitionV1):
        def to_mapping(self) -> dict[str, object]:
            raise RuntimeError("unexpected transition mapping")

    class ExplodingStep(runtime_lifecycle.StepV1):
        def to_mapping(self) -> dict[str, object]:
            raise RuntimeError("unexpected step mapping")

    class ExplodingJournal(runtime_lifecycle.D320CutoverJournalV1):
        @property
        def payload(self) -> dict[str, object]:
            raise RuntimeError("unexpected journal payload")

    evidence = ExplodingEvidence(
        runtime_lifecycle._d320_canonical_json(evidence_mapping)
    )
    snapshot = ExplodingSnapshot(
        runtime_lifecycle._d320_canonical_json(snapshot_mapping)
    )
    transition = ExplodingTransition(
        runtime_lifecycle._d320_canonical_json(transition_mapping)
    )
    step = ExplodingStep(runtime_lifecycle._d320_canonical_json(step_mapping))
    expected_journal = runtime_lifecycle.D320CutoverJournalV1.from_payload(
        journal_mapping
    )
    journal = ExplodingJournal(expected_journal.payload_bytes)

    assert runtime_lifecycle.EvidenceBlobV1.to_mapping(evidence) == evidence_mapping
    assert snapshot.present is True
    assert runtime_lifecycle.ByteSnapshotV1.to_mapping(snapshot) == snapshot_mapping
    assert runtime_lifecycle.TransitionV1.to_mapping(transition) == transition_mapping
    assert (step.status, step.index, step.has_inverse) == ("INTENT", 0, False)
    assert runtime_lifecycle.StepV1.to_mapping(step) == step_mapping
    assert journal.payload_bytes == expected_journal.payload_bytes
    assert journal.to_bytes() == expected_journal.to_bytes()
    assert (
        runtime_lifecycle.D320CutoverJournalV1.payload.fget(journal) == journal_mapping
    )


@pytest.mark.parametrize(
    ("carrier", "mapping"),
    (
        (runtime_lifecycle.EvidenceBlobV1, _d332_blob("wrapper-evidence")),
        (
            runtime_lifecycle.ByteSnapshotV1,
            _d332_snapshot("pointer", b"wrapper-snapshot"),
        ),
        (
            runtime_lifecycle.TransitionV1,
            {
                "sequence": 1,
                "from": "ABSENT",
                "to": "PREFLIGHTED",
                "at_unix_ms": 1,
                "reason_code": "preflight",
            },
        ),
        (
            runtime_lifecycle.StepV1,
            _d332_step(status="INTENT", inverse=False),
        ),
    ),
)
@pytest.mark.parametrize("behavior", ("raises", "forges"))
def test_d339_wrapper_factories_reject_subclass_factory_dispatch(
    carrier,
    mapping: dict[str, object],
    behavior: str,
) -> None:
    calls: list[bytes] = []

    def overridden_factory(cls, payload_bytes: bytes) -> object:
        calls.append(payload_bytes)
        if behavior == "raises":
            raise RuntimeError("factory dynamic dispatch")
        return bytes.__new__(cls, b"{}")

    subclass = type(
        f"Exploding{carrier.__name__}",
        (carrier,),
        {"_from_validated": classmethod(overridden_factory)},
    )

    with pytest.raises(
        runtime_lifecycle.D320CutoverJournalError,
        match="d320_wrapper_factory_type_invalid",
    ):
        subclass.from_mapping(mapping)
    assert calls == []


@pytest.mark.parametrize(
    ("carrier", "mapping", "view", "expected"),
    (
        (
            runtime_lifecycle.EvidenceBlobV1,
            _d332_blob("base-evidence"),
            runtime_lifecycle.EvidenceBlobV1.to_mapping,
            _d332_blob("base-evidence"),
        ),
        (
            runtime_lifecycle.ByteSnapshotV1,
            _d332_snapshot("pointer", b"base-snapshot"),
            lambda wrapper: (
                runtime_lifecycle.ByteSnapshotV1.present.fget(wrapper),
                runtime_lifecycle.ByteSnapshotV1.to_mapping(wrapper),
            ),
            (True, _d332_snapshot("pointer", b"base-snapshot")),
        ),
        (
            runtime_lifecycle.TransitionV1,
            {
                "sequence": 1,
                "from": "ABSENT",
                "to": "PREFLIGHTED",
                "at_unix_ms": 1,
                "reason_code": "preflight",
            },
            runtime_lifecycle.TransitionV1.to_mapping,
            {
                "sequence": 1,
                "from": "ABSENT",
                "to": "PREFLIGHTED",
                "at_unix_ms": 1,
                "reason_code": "preflight",
            },
        ),
        (
            runtime_lifecycle.StepV1,
            _d332_step(status="INTENT", inverse=False),
            lambda wrapper: (
                runtime_lifecycle.StepV1.status.fget(wrapper),
                runtime_lifecycle.StepV1.index.fget(wrapper),
                runtime_lifecycle.StepV1.has_inverse.fget(wrapper),
                runtime_lifecycle.StepV1.to_mapping(wrapper),
            ),
            ("INTENT", 0, False, _d332_step(status="INTENT", inverse=False)),
        ),
    ),
)
def test_d339_wrapper_base_factories_emit_revalidated_canonical_carriers(
    carrier,
    mapping: dict[str, object],
    view,
    expected: object,
) -> None:
    wrapper = carrier.from_mapping(mapping)

    assert type(wrapper) is carrier
    assert bytes(wrapper) == runtime_lifecycle._d320_canonical_json(mapping)
    assert view(wrapper) == expected


def test_d340_recovery_revalidates_forged_carriers_without_dispatch() -> None:
    payload = _d332_payload_with_history(runtime_lifecycle._D320_NORMAL_STATES[1:])
    journal = runtime_lifecycle.D320CutoverJournalV1.from_payload(payload)
    observed = _d332_new_snapshots(payload)
    snapshot_mapping = runtime_lifecycle.ByteSnapshotV1.to_mapping(observed["pointer"])
    evidence_mapping = runtime_lifecycle.EvidenceBlobV1.to_mapping(
        observed["unit_status"]
    )
    journal_bytes = journal.to_bytes()
    calls = {"snapshot": 0, "evidence": 0, "journal": 0}

    class ForgedSnapshot(runtime_lifecycle.ByteSnapshotV1):
        def to_mapping(self) -> dict[str, object]:
            calls["snapshot"] += 1
            return snapshot_mapping

    class ForgedEvidence(runtime_lifecycle.EvidenceBlobV1):
        def to_mapping(self) -> dict[str, object]:
            calls["evidence"] += 1
            return evidence_mapping

    class ForgedJournal(runtime_lifecycle.D320CutoverJournalV1):
        def to_bytes(self) -> bytes:
            calls["journal"] += 1
            return journal_bytes

    forged_observed: dict[str, object] = {
        name: bytes.__new__(ForgedSnapshot, b"{}")
        for name in runtime_lifecycle._D320_SNAPSHOT_NAMES
    }
    forged_observed["unit_status"] = bytes.__new__(ForgedEvidence, b"{}")

    classification = runtime_lifecycle.classify_d320_recovery(
        journal, observed=forged_observed
    )
    assert (classification.kind, classification.state) == (
        "UNREADABLE_BLOCKED",
        "BLOCKED",
    )
    assert calls == {"snapshot": 0, "evidence": 0, "journal": 0}

    classification = runtime_lifecycle.classify_d320_recovery(
        bytes.__new__(ForgedJournal, b"{}"), observed=observed
    )
    assert (classification.kind, classification.state) == (
        "UNREADABLE_BLOCKED",
        "BLOCKED",
    )
    assert calls == {"snapshot": 0, "evidence": 0, "journal": 0}

    previous_payload = _d334_normal_payload("PREFLIGHTED")
    previous = runtime_lifecycle.D320CutoverJournalV1.from_payload(previous_payload)
    blocked = runtime_lifecycle.D320CutoverJournalV1.from_payload(
        _d334_blocked_successor(previous_payload, reason="unreadable")
    )
    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.validate_d320_journal_successor(
            previous,
            blocked,
            observed={
                **_d332_old_snapshots(previous_payload),
                "pointer": bytes.__new__(ForgedSnapshot, b"{}"),
            },
        )
    assert calls == {"snapshot": 0, "evidence": 0, "journal": 0}


def test_d341_d320_byte_entries_ignore_forged_bytes_dispatch() -> None:
    payload = _d334_normal_payload("LIVE_GRANTED")
    journal = runtime_lifecycle.D320CutoverJournalV1.from_payload(payload)
    envelope_bytes = journal.to_bytes()
    payload_bytes = journal.payload_bytes
    observed = _d332_new_snapshots(payload)
    assert (
        runtime_lifecycle.classify_d320_recovery(journal, observed=observed).kind
        == "ALL_NEW_VERIFIED"
    )

    calls = {
        "envelope": 0,
        "evidence": 0,
        "snapshot": 0,
        "transition": 0,
        "step": 0,
        "journal": 0,
    }

    class ForgedEnvelope(bytes):
        def __bytes__(self) -> bytes:
            calls["envelope"] += 1
            return envelope_bytes

    forged_envelope = bytes.__new__(ForgedEnvelope, b"{}")
    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.D320CutoverJournalV1.from_bytes(forged_envelope)
    assert (
        runtime_lifecycle.classify_d320_recovery(
            forged_envelope, observed=observed
        ).kind
        == "UNREADABLE_BLOCKED"
    )
    restored = runtime_lifecycle.D320CutoverJournalV1.from_bytes(envelope_bytes)
    assert type(restored) is runtime_lifecycle.D320CutoverJournalV1
    assert restored.payload == journal.payload

    constructors = (
        (
            "evidence",
            runtime_lifecycle.EvidenceBlobV1,
            runtime_lifecycle._d320_canonical_json(_d332_blob("r18-evidence")),
        ),
        (
            "snapshot",
            runtime_lifecycle.ByteSnapshotV1,
            runtime_lifecycle._d320_canonical_json(
                _d332_snapshot("pointer", b"r18-snapshot")
            ),
        ),
        (
            "transition",
            runtime_lifecycle.TransitionV1,
            runtime_lifecycle._d320_canonical_json(
                {
                    "sequence": 1,
                    "from": "ABSENT",
                    "to": "PREFLIGHTED",
                    "at_unix_ms": 1,
                    "reason_code": "r18-transition",
                }
            ),
        ),
        (
            "step",
            runtime_lifecycle.StepV1,
            runtime_lifecycle._d320_canonical_json(
                _d332_step(status="INTENT", inverse=False)
            ),
        ),
        (
            "journal",
            runtime_lifecycle.D320CutoverJournalV1,
            payload_bytes,
        ),
    )
    for name, constructor, replacement in constructors:

        class ForgedCarrier(bytes):
            def __bytes__(self) -> bytes:
                calls[name] += 1
                return replacement

        forged = bytes.__new__(ForgedCarrier, b"{}")
        with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
            constructor(forged)
        valid = constructor(replacement)
        assert type(valid) is constructor

    assert calls == {
        "envelope": 0,
        "evidence": 0,
        "snapshot": 0,
        "transition": 0,
        "step": 0,
        "journal": 0,
    }


def test_d340_from_bytes_uses_one_cumulative_traversal_budget(monkeypatch) -> None:
    journal = runtime_lifecycle.D320CutoverJournalV1.from_payload(_d332_payload())
    raw = journal.to_bytes()
    visits: list[tuple[int, int]] = []
    visit = runtime_lifecycle._d320_visit_json_entry

    def instrumented_visit(budget) -> None:
        visit(budget)
        visits.append((id(budget), budget.entries))

    monkeypatch.setattr(runtime_lifecycle, "_d320_visit_json_entry", instrumented_visit)
    runtime_lifecycle.D320CutoverJournalV1.from_bytes(raw)
    cumulative_entries = max(entries for _identifier, entries in visits)
    assert {identifier for identifier, _entries in visits} == {visits[0][0]}

    envelope = runtime_lifecycle._d320_parse_json(raw[:-1])
    assert isinstance(envelope, dict)
    payload = envelope["payload"]
    phase_entries: list[int] = []
    for action in (
        lambda budget: runtime_lifecycle._d320_json_value(
            envelope, semantic=False, budget=budget
        ),
        lambda budget: runtime_lifecycle._d320_syntax_json(payload, budget=budget),
        lambda budget: runtime_lifecycle._d320_canonical_json(payload, budget=budget),
        lambda budget: runtime_lifecycle.D320CutoverJournalV1(
            runtime_lifecycle._d320_canonical_json(payload), budget=budget
        ),
    ):
        budget = runtime_lifecycle._D320JsonTraversalBudget()
        action(budget)
        phase_entries.append(budget.entries)

    assert max(phase_entries) < cumulative_entries
    monkeypatch.setattr(
        runtime_lifecycle,
        "_D320_MAX_JSON_ENTRIES",
        cumulative_entries + 1,
    )
    runtime_lifecycle.D320CutoverJournalV1.from_bytes(raw)

    monkeypatch.setattr(
        runtime_lifecycle,
        "_D320_MAX_JSON_ENTRIES",
        max(phase_entries) + 1,
    )
    with pytest.raises(
        runtime_lifecycle.D320CutoverJournalError,
        match="d320_json_entries_invalid",
    ):
        runtime_lifecycle.D320CutoverJournalV1.from_bytes(raw)


def test_d332_recovery_classifies_all_old_and_all_new_without_effects() -> None:
    old_payload = _d332_payload()
    old_journal = runtime_lifecycle.D320CutoverJournalV1.from_payload(old_payload)
    old = _d332_old_snapshots(old_payload)

    all_old = runtime_lifecycle.classify_d320_recovery(old_journal, observed=old)
    assert (all_old.kind, all_old.state, all_old.inverse_step_indexes) == (
        "ALL_OLD_VERIFIED",
        "ROLLED_BACK",
        (),
    )

    new_payload = _d332_payload(
        state="USER_CUTOVER_VERIFIED",
        sequence=7,
        steps=[_d332_step()],
    )
    new_journal = runtime_lifecycle.D320CutoverJournalV1.from_payload(new_payload)
    all_new = runtime_lifecycle.classify_d320_recovery(
        new_journal,
        observed=_d332_new_snapshots(new_payload),
    )
    assert (all_new.kind, all_new.state, all_new.inverse_step_indexes) == (
        "ALL_NEW_VERIFIED",
        "USER_CUTOVER_VERIFIED",
        (),
    )


def test_d332_recovery_classifies_mixed_and_all_block_classes() -> None:
    payload = _d332_payload(
        state="USER_CUTOVER_VERIFIED",
        sequence=7,
        steps=[_d332_step(index=0, inverse=True), _d332_step(index=1, inverse=True)],
    )
    journal = runtime_lifecycle.D320CutoverJournalV1.from_payload(payload)
    old = _d332_old_snapshots(payload)
    new = _d332_new_snapshots(payload)
    mixed = dict(old)
    mixed["pointer"] = new["pointer"]

    invertible = runtime_lifecycle.classify_d320_recovery(journal, observed=mixed)
    assert (invertible.kind, invertible.state, invertible.inverse_step_indexes) == (
        "MIXED_INVERTIBLE",
        "ABORTING",
        (1, 0),
    )

    noninvertible_payload = copy.deepcopy(payload)
    noninvertible_payload["steps"][1]["inverse"] = None
    noninvertible = runtime_lifecycle.classify_d320_recovery(
        runtime_lifecycle.D320CutoverJournalV1.from_payload(noninvertible_payload),
        observed=mixed,
    )
    assert noninvertible.kind == "NONINVERTIBLE_BLOCKED"
    assert noninvertible.state == "BLOCKED"

    unknown = dict(mixed)
    unknown["pointer"] = runtime_lifecycle.ByteSnapshotV1.from_mapping(
        _d332_snapshot("pointer", b"neither-old-nor-new")
    )
    blocked = runtime_lifecycle.classify_d320_recovery(journal, observed=unknown)
    assert blocked.kind == "MIXED_BLOCKED"
    assert blocked.state == "BLOCKED"

    unreadable = runtime_lifecycle.classify_d320_recovery(
        b"not-a-journal\n", observed=mixed
    )
    assert (unreadable.kind, unreadable.state) == ("UNREADABLE_BLOCKED", "BLOCKED")


@pytest.mark.parametrize(
    ("status", "expected"),
    (
        ("INTENT", ("NONINVERTIBLE_BLOCKED", "BLOCKED", ())),
        ("EFFECT_STARTED", ("NONINVERTIBLE_BLOCKED", "BLOCKED", ())),
        ("VERIFIED", ("MIXED_INVERTIBLE", "ABORTING", (0,))),
        ("INVERSE_INTENT", ("NONINVERTIBLE_BLOCKED", "BLOCKED", ())),
        ("INVERSE_VERIFIED", ("NONINVERTIBLE_BLOCKED", "BLOCKED", ())),
    ),
)
def test_d332_hard_abort_at_every_modeled_commitpoint_is_pure(
    status: str, expected: tuple[str, str, tuple[int, ...]]
) -> None:
    payload = (
        _d332_payload_with_history(("PREFLIGHTED", "ABORTING"))
        if status in {"INVERSE_INTENT", "INVERSE_VERIFIED"}
        else _d332_payload(
            state="USER_CUTOVER_IN_PROGRESS",
            sequence=6,
        )
    )
    payload["steps"] = [_d332_step(status=status, inverse=True)]
    journal = runtime_lifecycle.D320CutoverJournalV1.from_payload(payload)
    old = _d332_old_snapshots(payload)
    new = _d332_new_snapshots(payload)
    observed = dict(old)
    observed["pointer"] = new["pointer"]

    result = runtime_lifecycle.classify_d320_recovery(journal, observed=observed)

    assert (result.kind, result.state, result.inverse_step_indexes) == expected


def test_d332_model_never_calls_existing_mutators(monkeypatch) -> None:
    payload = _d332_payload()
    journal = runtime_lifecycle.D320CutoverJournalV1.from_payload(payload)
    old = _d332_old_snapshots(payload)

    def forbidden(*_args, **_kwargs):
        raise AssertionError("mutator reached")

    for name in (
        "cutover",
        "_install_attested_runtime",
        "_systemctl_mutate",
        "_cutover_systemctl_mutate",
        "_restore_bound_state",
        "_restore_bound_state_result",
        "_discard_new_generation",
        "_write_observation",
        "_publish_rollback_failure",
        "_atomic_restore",
        "_remove_legacy_hourly_units",
        "_revalidate_legacy_units",
        "_lifecycle_lock",
        "_private_directory",
        "_systemctl_default",
        "_observe_argumentless_installed_probe",
    ):
        monkeypatch.setattr(runtime_lifecycle, name, forbidden)

    assert (
        runtime_lifecycle.D320CutoverJournalV1.from_bytes(journal.to_bytes()) == journal
    )
    assert runtime_lifecycle.D320CutoverJournalV1.from_payload(payload) == journal
    successor = runtime_lifecycle.D320CutoverJournalV1.from_payload(
        _d332_payload(state="PREFLIGHTED", sequence=1)
    )
    runtime_lifecycle.validate_d320_journal_successor(journal, successor)
    runtime_lifecycle.validate_d324_lock_order(
        payload["lock_trace"], state="ABSENT", sequence=0, history=[]
    )
    assert (
        runtime_lifecycle.classify_d320_recovery(journal, observed=old).kind
        == "ALL_OLD_VERIFIED"
    )
    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.D320CutoverJournalV1.from_payload({"invalid": None})
    assert (
        runtime_lifecycle.classify_d320_recovery(b"invalid\n", observed=old).kind
        == "UNREADABLE_BLOCKED"
    )


@pytest.mark.parametrize(
    "mutation",
    (
        lambda payload: payload["source"].__setitem__("commit", "A" * 40),
        lambda payload: payload["digests"]["hooks"].__setitem__(
            "native_bee_event", "a" * 63
        ),
        lambda payload: payload["abi"].__setitem__("version", 2),
        lambda payload: payload["abi"]["root_receipt"].__setitem__("parent_chain", []),
        lambda payload: payload["native"].__setitem__("disabled", 1),
        lambda payload: payload["native"].__setitem__("adapter_version", "a" * 129),
        lambda payload: payload["precutover"]["pointer"].__setitem__("mode", 0o10000),
        lambda payload: payload["pins"].__setitem__(
            "current", ["generation-1", "generation-1"]
        ),
        lambda payload: payload.__setitem__("steps", [_d332_step(index=1)]),
    ),
)
def test_d332_payload_rejects_invalid_nested_areas_and_bounds(mutation) -> None:
    payload = _d332_payload()
    mutation(payload)

    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.D320CutoverJournalV1.from_payload(payload)


def _d332_history_for_states(states: tuple[str, ...]) -> list[dict[str, object]]:
    previous = "ABSENT"
    result: list[dict[str, object]] = []
    for sequence, state in enumerate(states, start=1):
        result.append(
            {
                "sequence": sequence,
                "from": previous,
                "to": state,
                "at_unix_ms": 100 + sequence,
                "reason_code": "unreadable" if state == "BLOCKED" else "transition",
            }
        )
        previous = state
    return result


def _d333_complete_lock_trace() -> list[dict[str, object]]:
    acquired = [
        {
            "event": "ACQUIRE",
            "lock": lock,
            "state": "PREFLIGHTED",
            "sequence": 1,
        }
        for lock in runtime_lifecycle.D324_LOCK_ORDER
    ]
    released = [
        {
            "event": "RELEASE",
            "lock": lock,
            "state": "ROLLED_BACK",
            "sequence": 3,
        }
        for lock in reversed(runtime_lifecycle.D324_LOCK_ORDER)
    ]
    return acquired + released


def _d332_payload_with_history(states: tuple[str, ...]) -> dict[str, object]:
    payload = _d332_payload(sequence=len(states))
    payload["state"] = states[-1]
    payload["history"] = _d332_history_for_states(states)
    payload["lock_trace"] = _d333_lock_trace(states[-1], len(states))
    if states[-1] in (
        "USER_CUTOVER_VERIFIED",
        "ISOLATED_HOOK_PROBE_VERIFIED",
        "MCP_HANDSHAKE_VERIFIED",
        "LIVE_GRANTED",
    ):
        payload["steps"] = [_d332_step()]
    return payload


def _d334_normal_payload(state: str) -> dict[str, object]:
    if state == "ABSENT":
        return _d332_payload()
    index = runtime_lifecycle._D320_NORMAL_STATES.index(state)
    return _d332_payload_with_history(
        runtime_lifecycle._D320_NORMAL_STATES[1 : index + 1]
    )


def _d334_blocked_successor(
    previous: dict[str, object], *, reason: str
) -> dict[str, object]:
    successor = copy.deepcopy(previous)
    successor["sequence"] = int(previous["sequence"]) + 1
    successor["updated_unix_ms"] = int(previous["updated_unix_ms"]) + 1
    successor["state"] = "BLOCKED"
    history = successor["history"]
    assert isinstance(history, list)
    history.append(
        {
            "sequence": successor["sequence"],
            "from": previous["state"],
            "to": "BLOCKED",
            "at_unix_ms": successor["updated_unix_ms"],
            "reason_code": reason,
        }
    )
    if previous["state"] != "ABSENT":
        trace = successor["lock_trace"]
        assert isinstance(trace, list)
        trace.append(
            {
                "event": "RELEASE",
                "lock": "D324-Journallock",
                "state": "BLOCKED",
                "sequence": successor["sequence"],
            }
        )
    return successor


def test_d332_history_covers_bound_graph_and_rejects_a_gap() -> None:
    normal = (
        "PREFLIGHTED",
        "ROOT_ABI_VERIFIED",
        "NATIVE_PREPARED_DISABLED",
        "NATIVE_TRUST_VERIFIED_DISABLED",
        "NATIVE_COMMITTED_DISABLED",
        "USER_CUTOVER_IN_PROGRESS",
        "USER_CUTOVER_VERIFIED",
        "ISOLATED_HOOK_PROBE_VERIFIED",
        "MCP_HANDSHAKE_VERIFIED",
        "LIVE_GRANTED",
    )
    runtime_lifecycle.D320CutoverJournalV1.from_payload(
        _d332_payload_with_history(normal)
    )
    runtime_lifecycle.D320CutoverJournalV1.from_payload(
        _d332_payload_with_history(normal[:7] + ("ABORTING", "ROLLED_BACK"))
    )
    runtime_lifecycle.D320CutoverJournalV1.from_payload(
        _d332_payload_with_history(("PREFLIGHTED", "BLOCKED"))
    )

    invalid = _d332_payload_with_history(("ROOT_ABI_VERIFIED",))
    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.D320CutoverJournalV1.from_payload(invalid)


@pytest.mark.parametrize(
    ("before", "after"),
    (
        ("ABSENT", "PREFLIGHTED"),
        ("PREFLIGHTED", "ROOT_ABI_VERIFIED"),
        ("ROOT_ABI_VERIFIED", "NATIVE_PREPARED_DISABLED"),
        ("NATIVE_PREPARED_DISABLED", "NATIVE_TRUST_VERIFIED_DISABLED"),
        ("NATIVE_TRUST_VERIFIED_DISABLED", "NATIVE_COMMITTED_DISABLED"),
        ("NATIVE_COMMITTED_DISABLED", "USER_CUTOVER_IN_PROGRESS"),
        ("USER_CUTOVER_IN_PROGRESS", "USER_CUTOVER_VERIFIED"),
        ("USER_CUTOVER_VERIFIED", "ISOLATED_HOOK_PROBE_VERIFIED"),
        ("ISOLATED_HOOK_PROBE_VERIFIED", "MCP_HANDSHAKE_VERIFIED"),
        ("MCP_HANDSHAKE_VERIFIED", "LIVE_GRANTED"),
        ("PREFLIGHTED", "ABORTING"),
        ("ABORTING", "ROLLED_BACK"),
        ("PREFLIGHTED", "BLOCKED"),
    ),
)
def test_d332_each_bound_transition_is_valid(before: str, after: str) -> None:
    transition = {
        "sequence": 0,
        "from": before,
        "to": after,
        "at_unix_ms": 1,
        "reason_code": "unreadable" if after == "BLOCKED" else "transition",
    }

    assert (
        runtime_lifecycle.TransitionV1.from_mapping(transition).to_mapping()
        == transition
    )


@pytest.mark.parametrize(
    "status",
    ("INTENT", "EFFECT_STARTED", "VERIFIED", "INVERSE_INTENT", "INVERSE_VERIFIED"),
)
def test_d332_each_step_phase_is_individually_validated(status: str) -> None:
    assert (
        runtime_lifecycle.StepV1.from_mapping(
            _d332_step(status=status, inverse=True)
        ).status
        == status
    )


@pytest.mark.parametrize("index", range(len(_d333_complete_lock_trace())))
def test_d332_each_lock_duplicate_is_rejected(index: int) -> None:
    trace = _d333_complete_lock_trace()
    history = _d332_history_for_states(("PREFLIGHTED", "ABORTING", "ROLLED_BACK"))
    trace.insert(index, trace[index])

    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.validate_d324_lock_order(
            trace, state="ROLLED_BACK", sequence=3, history=history
        )


@pytest.mark.parametrize("index", range(len(runtime_lifecycle.D324_LOCK_ORDER) - 1))
def test_d332_each_adjacent_lock_inversion_is_rejected(index: int) -> None:
    trace = _d333_complete_lock_trace()
    history = _d332_history_for_states(("PREFLIGHTED", "ABORTING", "ROLLED_BACK"))
    trace[index], trace[index + 1] = trace[index + 1], trace[index]

    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.validate_d324_lock_order(
            trace, state="ROLLED_BACK", sequence=3, history=history
        )


def test_d333_postcutover_and_unit_status_are_bound_recovery_inputs() -> None:
    payload = _d332_payload(
        state="USER_CUTOVER_VERIFIED",
        sequence=7,
        steps=[_d332_step()],
    )
    journal = runtime_lifecycle.D320CutoverJournalV1.from_payload(payload)
    observed = _d332_new_snapshots(payload)
    assert (
        runtime_lifecycle.classify_d320_recovery(journal, observed=observed).kind
        == "ALL_NEW_VERIFIED"
    )

    unit_drift = dict(observed)
    unit_drift["unit_status"] = runtime_lifecycle.EvidenceBlobV1.from_mapping(
        _d332_blob("unit_status", b"unit-drift")
    )
    assert (
        runtime_lifecycle.classify_d320_recovery(journal, observed=unit_drift).kind
        == "MIXED_BLOCKED"
    )
    missing_unit = dict(observed)
    del missing_unit["unit_status"]
    assert (
        runtime_lifecycle.classify_d320_recovery(journal, observed=missing_unit).kind
        == "UNREADABLE_BLOCKED"
    )

    substituted = copy.deepcopy(payload)
    substituted["postcutover"]["pointer"] = _d332_snapshot(
        "pointer", b"substituted-new"
    )
    assert (
        runtime_lifecycle.classify_d320_recovery(
            runtime_lifecycle.D320CutoverJournalV1.from_payload(substituted),
            observed=observed,
        ).kind
        == "MIXED_BLOCKED"
    )
    missing_postcutover = copy.deepcopy(payload)
    del missing_postcutover["postcutover"]
    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.D320CutoverJournalV1.from_payload(missing_postcutover)
    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.D320CutoverJournalV1.from_payload(
            _d332_payload(state="USER_CUTOVER_VERIFIED", sequence=7)
        )


@pytest.mark.parametrize(
    "state",
    (
        "USER_CUTOVER_VERIFIED",
        "ISOLATED_HOOK_PROBE_VERIFIED",
        "MCP_HANDSHAKE_VERIFIED",
        "LIVE_GRANTED",
    ),
)
def test_d336_all_new_recovery_stays_verified_after_each_gate(state: str) -> None:
    payload = _d334_normal_payload(state)
    journal = runtime_lifecycle.D320CutoverJournalV1.from_payload(payload)

    classification = runtime_lifecycle.classify_d320_recovery(
        journal, observed=_d332_new_snapshots(payload)
    )

    assert classification.kind == "ALL_NEW_VERIFIED"
    assert classification.state == "USER_CUTOVER_VERIFIED"
    assert classification.inverse_step_indexes == ()


def test_d333_wrappers_and_exported_paths_revalidate_fail_closed() -> None:
    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.D320CutoverJournalV1(b"{}")
    for wrapper in (
        runtime_lifecycle.ByteSnapshotV1,
        runtime_lifecycle.EvidenceBlobV1,
        runtime_lifecycle.StepV1,
        runtime_lifecycle.TransitionV1,
    ):
        with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
            wrapper({"invalid": None})

    forged = bytes.__new__(runtime_lifecycle.D320CutoverJournalV1, b"{}")
    payload = _d332_payload()
    observed = _d332_old_snapshots(payload)
    assert (
        runtime_lifecycle.classify_d320_recovery(forged, observed=observed).kind
        == "UNREADABLE_BLOCKED"
    )
    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.validate_d320_journal_successor(forged, forged)

    forged_snapshot = bytes.__new__(runtime_lifecycle.ByteSnapshotV1, b"{}")
    observed_with_forgery = dict(observed)
    observed_with_forgery["pointer"] = forged_snapshot
    assert (
        runtime_lifecycle.classify_d320_recovery(
            runtime_lifecycle.D320CutoverJournalV1.from_payload(payload),
            observed=observed_with_forgery,
        ).kind
        == "UNREADABLE_BLOCKED"
    )

    forged_evidence = bytes.__new__(runtime_lifecycle.EvidenceBlobV1, b"{}")
    forged_step = bytes.__new__(runtime_lifecycle.StepV1, b"{}")
    forged_transition = bytes.__new__(runtime_lifecycle.TransitionV1, b"{}")
    for wrapper in (forged_evidence, forged_step, forged_transition):
        with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
            wrapper.to_mapping()
    observed_with_forged_unit = dict(observed)
    observed_with_forged_unit["unit_status"] = forged_evidence
    assert (
        runtime_lifecycle.classify_d320_recovery(
            runtime_lifecycle.D320CutoverJournalV1.from_payload(payload),
            observed=observed_with_forged_unit,
        ).kind
        == "UNREADABLE_BLOCKED"
    )


@pytest.mark.parametrize("wrapper", ("evidence", "snapshot", "transition", "step"))
def test_d335_mapping_wrappers_are_semantically_immutable(wrapper: str) -> None:
    values: dict[str, tuple[object, str, object, object]] = {
        "evidence": (_d332_blob("blob"), "kind", "before", "after"),
        "snapshot": (
            _d332_snapshot("pointer", b"pointer"),
            "name",
            "before_pointer",
            "after_pointer",
        ),
        "transition": (
            {
                "sequence": 0,
                "from": "ABSENT",
                "to": "PREFLIGHTED",
                "at_unix_ms": 1,
                "reason_code": "transition",
            },
            "reason_code",
            "before",
            "after",
        ),
        "step": (_d332_step(status="INTENT"), "operation", "before", "after"),
    }
    factories = {
        "evidence": runtime_lifecycle.EvidenceBlobV1,
        "snapshot": runtime_lifecycle.ByteSnapshotV1,
        "transition": runtime_lifecycle.TransitionV1,
        "step": runtime_lifecycle.StepV1,
    }
    value, field, before, after = values[wrapper]
    assert isinstance(value, dict)
    value[field] = before
    expected = copy.deepcopy(value)
    instance = factories[wrapper].from_mapping(value)

    value[field] = after
    returned = instance.to_mapping()
    returned[field] = "mapping-copy-mutation"

    assert instance.to_mapping() == expected
    assert isinstance(instance, bytes)
    assert not hasattr(instance, "__dict__")


def test_d336_carriers_have_no_writable_truth_slot() -> None:
    journal_payload = _d332_payload()
    carriers: tuple[tuple[type[bytes], object, object], ...] = (
        (
            runtime_lifecycle.EvidenceBlobV1,
            runtime_lifecycle.EvidenceBlobV1.from_mapping(_d332_blob("blob")),
            lambda carrier: carrier.to_mapping(),
        ),
        (
            runtime_lifecycle.ByteSnapshotV1,
            runtime_lifecycle.ByteSnapshotV1.from_mapping(
                _d332_snapshot("pointer", b"pointer")
            ),
            lambda carrier: carrier.to_mapping(),
        ),
        (
            runtime_lifecycle.TransitionV1,
            runtime_lifecycle.TransitionV1.from_mapping(
                {
                    "sequence": 0,
                    "from": "ABSENT",
                    "to": "PREFLIGHTED",
                    "at_unix_ms": 1,
                    "reason_code": "transition",
                }
            ),
            lambda carrier: carrier.to_mapping(),
        ),
        (
            runtime_lifecycle.StepV1,
            runtime_lifecycle.StepV1.from_mapping(_d332_step(status="INTENT")),
            lambda carrier: carrier.to_mapping(),
        ),
        (
            runtime_lifecycle.D320CutoverJournalV1,
            runtime_lifecycle.D320CutoverJournalV1.from_payload(journal_payload),
            lambda carrier: carrier.payload,
        ),
    )
    for carrier_type, carrier, view in carriers:
        assert isinstance(carrier, carrier_type)
        assert isinstance(carrier, bytes)
        assert not hasattr(carrier, "__dict__")
        assert not hasattr(carrier, "_payload_bytes")
        expected = view(carrier)
        with pytest.raises(AttributeError):
            object.__setattr__(carrier, "_payload_bytes", b"{}")
        assert view(carrier) == expected
        with pytest.raises(TypeError):
            object.__new__(carrier_type)
        forged = bytes.__new__(carrier_type, b"{}")
        with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
            view(forged)


def test_d335_public_mapping_inputs_are_bounded_and_cycle_safe() -> None:
    factories = (
        runtime_lifecycle.D320CutoverJournalV1.from_payload,
        runtime_lifecycle.EvidenceBlobV1.from_mapping,
        runtime_lifecycle.ByteSnapshotV1.from_mapping,
        runtime_lifecycle.TransitionV1.from_mapping,
        runtime_lifecycle.StepV1.from_mapping,
    )
    deep: object = []
    for _index in range(2_000):
        deep = [deep]
    cycle_list: list[object] = []
    cycle_list.append(cycle_list)
    cycle_map: dict[str, object] = {}
    cycle_map["self"] = cycle_map
    for invalid in ({"unexpected": deep}, {"unexpected": cycle_list}, cycle_map):
        for factory in factories:
            with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
                factory(invalid)

    node_limited = {
        "unexpected": [
            [] for _index in range(runtime_lifecycle._D320_MAX_CONTAINER_NODES)
        ]
    }
    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.D320CutoverJournalV1.from_payload(node_limited)


def test_d336_public_mapping_entry_budget_consumes_only_the_surplus() -> None:
    class ForeignMapping(Mapping[str, object]):
        def __init__(self, *, finite: bool) -> None:
            self.finite = finite
            self.visited = 0

        def __len__(self) -> int:
            return 1

        def __iter__(self):
            while (
                not self.finite
                or self.visited <= runtime_lifecycle._D320_MAX_JSON_ENTRIES
            ):
                self.visited += 1
                yield f"entry-{self.visited}"

        def __getitem__(self, _key: str) -> object:
            return None

    for finite in (True, False):
        foreign = ForeignMapping(finite=finite)
        with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
            runtime_lifecycle.D320CutoverJournalV1.from_payload(foreign)
        assert foreign.visited == runtime_lifecycle._D320_MAX_JSON_ENTRIES + 1


def test_d336_syntax_digest_precedes_semantic_surrogate_rejection() -> None:
    surrogate_payload = b'{"sequence":"\\ud800"}'
    raw = (
        b'{"content_sha256":"'
        + b"0" * 64
        + b'","payload":'
        + surrogate_payload
        + b"}\n"
    )
    with pytest.raises(
        runtime_lifecycle.D320CutoverJournalError,
        match="d320_envelope_digest_invalid",
    ):
        runtime_lifecycle.D320CutoverJournalV1.from_bytes(raw)

    valid_payload = runtime_lifecycle._d320_canonical_json(_d332_payload())
    assert (
        runtime_lifecycle._d320_syntax_json(
            runtime_lifecycle._d320_parse_json(valid_payload)
        )
        == valid_payload
    )


def test_d336_recovery_observed_budget_is_shared_across_all_artifacts() -> None:
    class StatefulArtifactMapping(dict[str, object]):
        def __init__(self, value: Mapping[str, object]) -> None:
            super().__init__(value)
            self.first_items_call = True
            self.visited = 0

        def items(self):
            if not self.first_items_call:
                return super().items()
            self.first_items_call = False

            def oversized_items():
                for index in range(runtime_lifecycle._D320_MAX_JSON_ENTRIES):
                    self.visited += 1
                    yield (f"entry-{index}", None)

            return oversized_items()

    payload = _d334_normal_payload("LIVE_GRANTED")
    observed = _d332_new_snapshots(payload)
    stateful_observed = {
        name: StatefulArtifactMapping(value.to_mapping())
        for name, value in observed.items()
    }

    classification = runtime_lifecycle.classify_d320_recovery(
        runtime_lifecycle.D320CutoverJournalV1.from_payload(payload),
        observed=stateful_observed,
    )

    assert classification.kind == "UNREADABLE_BLOCKED"
    assert sum(value.visited for value in stateful_observed.values()) == (
        runtime_lifecycle._D320_MAX_JSON_ENTRIES
        - len(runtime_lifecycle._D320_ARTIFACT_NAMES)
        + 1
    )


def test_d336_blocked_successor_normalizes_observed_once_under_one_budget() -> None:
    class StatefulArtifactMapping(dict[str, object]):
        def __init__(self) -> None:
            super().__init__(_d332_snapshot("pointer", b"old-pointer"))
            self.items_calls = 0
            self.visited = 0

        def items(self):
            self.items_calls += 1

            def forty_thousand_items():
                for index in range(40_000):
                    self.visited += 1
                    yield (f"entry-{self.items_calls}-{index}", None)

            return forty_thousand_items()

    previous_payload = _d334_normal_payload("PREFLIGHTED")
    previous = runtime_lifecycle.D320CutoverJournalV1.from_payload(previous_payload)
    reference_successor = runtime_lifecycle.D320CutoverJournalV1.from_payload(
        _d334_blocked_successor(
            previous_payload, reason="mixed_without_complete_inverse"
        )
    )
    reference_observed = _d332_old_snapshots(previous_payload)
    reference_observed["pointer"] = runtime_lifecycle.ByteSnapshotV1.from_mapping(
        _d332_snapshot("pointer", b"neither-old-nor-new")
    )
    runtime_lifecycle.validate_d320_journal_successor(
        previous, reference_successor, observed=reference_observed
    )

    successor = runtime_lifecycle.D320CutoverJournalV1.from_payload(
        _d334_blocked_successor(previous_payload, reason="unreadable")
    )

    observed = _d332_old_snapshots(previous_payload)
    stateful = StatefulArtifactMapping()
    observed["pointer"] = stateful
    with pytest.raises(
        runtime_lifecycle.D320CutoverJournalError,
        match="d320_json_entries_invalid",
    ):
        runtime_lifecycle.validate_d320_journal_successor(
            previous, successor, observed=observed
        )
    assert stateful.items_calls == 1
    assert stateful.visited == 40_000


def test_d336_envelope_limit_applies_to_factory_and_direct_constructor() -> None:
    payload = _d332_payload(
        state="USER_CUTOVER_VERIFIED",
        sequence=7,
        steps=[_d332_step(index=index) for index in range(256)],
    )
    raw = b"x" * 3_000
    for step in payload["steps"]:
        assert isinstance(step, dict)
        index = int(step["index"])
        for field in ("preconditions", "readback", "adapter_receipt", "inverse"):
            step[field] = _d332_blob(f"{field}-{index}", raw)
    payload_bytes = runtime_lifecycle._d320_canonical_json(payload)
    assert (
        len(payload_bytes) + runtime_lifecycle._D320_ENVELOPE_FIXED_BYTES
        > runtime_lifecycle._D320_MAX_ENVELOPE_BYTES
    )

    with pytest.raises(
        runtime_lifecycle.D320CutoverJournalError,
        match="d320_envelope_too_large",
    ):
        runtime_lifecycle.D320CutoverJournalV1.from_payload(payload)
    with pytest.raises(
        runtime_lifecycle.D320CutoverJournalError,
        match="d320_envelope_too_large",
    ):
        runtime_lifecycle.D320CutoverJournalV1(payload_bytes)


def test_d336_forged_list_journal_carrier_fails_closed_at_every_public_view() -> None:
    forged = bytes.__new__(runtime_lifecycle.D320CutoverJournalV1, b"[]")
    valid = runtime_lifecycle.D320CutoverJournalV1.from_payload(_d332_payload())

    for view in (
        lambda: forged.payload,
        lambda: forged.payload_bytes,
        lambda: forged.to_bytes(),
    ):
        with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
            view()
    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.validate_d320_journal_successor(forged, valid)


def test_d335_json_and_foreign_mapping_inputs_fail_closed() -> None:
    payload = b'{"unexpected":' + b"[" * 65 + b"0" + b"]" * 65 + b"}"
    raw = (
        b'{"content_sha256":"'
        + hashlib.sha256(payload).hexdigest().encode("ascii")
        + b'","payload":'
        + payload
        + b"}\n"
    )
    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.D320CutoverJournalV1.from_bytes(raw)

    oversized_integer_payload = b'{"value":' + b"9" * 5_000 + b"}"
    oversized_integer_envelope = (
        b'{"content_sha256":"'
        + hashlib.sha256(oversized_integer_payload).hexdigest().encode("ascii")
        + b'","payload":'
        + oversized_integer_payload
        + b"}\n"
    )
    assert len(oversized_integer_envelope) < runtime_lifecycle._D320_MAX_ENVELOPE_BYTES
    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.D320CutoverJournalV1.from_bytes(oversized_integer_envelope)

    class ExplodingMapping(dict):
        def items(self):
            raise RuntimeError("foreign mapping failure")

    for factory in (
        runtime_lifecycle.D320CutoverJournalV1.from_payload,
        runtime_lifecycle.EvidenceBlobV1.from_mapping,
        runtime_lifecycle.ByteSnapshotV1.from_mapping,
        runtime_lifecycle.TransitionV1.from_mapping,
        runtime_lifecycle.StepV1.from_mapping,
    ):
        with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
            factory(ExplodingMapping())

    class ExplodingSequence(Sequence[object]):
        def __len__(self) -> int:
            raise RuntimeError("foreign sequence failure")

        def __getitem__(self, _index: int) -> object:
            raise AssertionError("must not be reached")

    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.validate_d324_lock_order(
            ExplodingSequence(), state="ABSENT", sequence=0, history=[]
        )


def test_d336_lock_order_normalizes_foreign_mappings_before_validation() -> None:
    class ForeignMapping(Mapping[str, object]):
        def __init__(self, value: Mapping[str, object]) -> None:
            self.value = value
            self.items_calls = 0
            self.iter_calls = 0

        def __getitem__(self, key: str) -> object:
            return self.value[key]

        def __iter__(self):
            self.iter_calls += 1
            return iter(self.value)

        def __len__(self) -> int:
            return len(self.value)

        def items(self):
            self.items_calls += 1
            return self.value.items()

    history = ForeignMapping(
        {
            "sequence": 1,
            "from": "ABSENT",
            "to": "PREFLIGHTED",
            "at_unix_ms": 1,
            "reason_code": "preflight",
        }
    )
    trace = ForeignMapping(
        {
            "event": "ACQUIRE",
            "lock": "D324-Journallock",
            "state": "PREFLIGHTED",
            "sequence": 1,
        }
    )

    runtime_lifecycle.validate_d324_lock_order(
        [trace], state="PREFLIGHTED", sequence=1, history=[history]
    )

    assert (history.items_calls, history.iter_calls) == (1, 0)
    assert (trace.items_calls, trace.iter_calls) == (1, 0)


def test_d336_lock_order_split_truth_mapping_keeps_first_truth() -> None:
    class SplitTruthTransition(Mapping[str, object]):
        first = {
            "sequence": 1,
            "from": "ABSENT",
            "to": "PREFLIGHTED",
            "at_unix_ms": 1,
            "reason_code": "preflight",
        }
        second = {**first, "at_unix_ms": 2, "reason_code": "second"}

        def __init__(self) -> None:
            self.items_calls = 0
            self.iter_calls = 0
            self.getitem_calls = 0

        def __getitem__(self, key: str) -> object:
            self.getitem_calls += 1
            return self.second[key]

        def __iter__(self):
            self.iter_calls += 1
            return iter(self.second)

        def __len__(self) -> int:
            return len(self.first)

        def items(self):
            self.items_calls += 1
            return self.first.items()

    transition = SplitTruthTransition()
    runtime_lifecycle.validate_d324_lock_order(
        [
            {
                "event": "ACQUIRE",
                "lock": "D324-Journallock",
                "state": "PREFLIGHTED",
                "sequence": 1,
            }
        ],
        state="PREFLIGHTED",
        sequence=1,
        history=[transition],
    )

    assert (
        transition.items_calls,
        transition.iter_calls,
        transition.getitem_calls,
    ) == (
        1,
        0,
        0,
    )


def test_d336_lock_order_rejects_sequence_length_iterator_disagreement() -> None:
    class ContradictorySequence(Sequence[object]):
        def __init__(self) -> None:
            self.iter_calls = 0

        def __getitem__(self, _index: int) -> object:
            raise AssertionError("iterator must be used")

        def __iter__(self):
            self.iter_calls += 1
            yield {"unexpected": None}

        def __len__(self) -> int:
            return 0

    history = ContradictorySequence()
    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.validate_d324_lock_order(
            [], state="ABSENT", sequence=0, history=history
        )
    assert history.iter_calls == 1


@pytest.mark.parametrize(
    ("carrier", "payload_bytes"),
    (
        (
            runtime_lifecycle.EvidenceBlobV1,
            runtime_lifecycle._d320_canonical_json(_d332_blob("evidence")),
        ),
        (
            runtime_lifecycle.ByteSnapshotV1,
            runtime_lifecycle._d320_canonical_json(
                _d332_snapshot("pointer", b"pointer")
            ),
        ),
        (
            runtime_lifecycle.TransitionV1,
            runtime_lifecycle._d320_canonical_json(
                {
                    "sequence": 1,
                    "from": "ABSENT",
                    "to": "PREFLIGHTED",
                    "at_unix_ms": 1,
                    "reason_code": "preflight",
                }
            ),
        ),
        (
            runtime_lifecycle.StepV1,
            runtime_lifecycle._d320_canonical_json(
                _d332_step(status="INTENT", inverse=False)
            ),
        ),
        (
            runtime_lifecycle.D320CutoverJournalV1,
            runtime_lifecycle._d320_canonical_json(_d332_payload()),
        ),
    ),
)
def test_d336_direct_carriers_copy_foreign_bytes_before_parsing(
    carrier,
    payload_bytes: bytes,
) -> None:
    class ExplodingBytes(bytes):
        def decode(self, *_args, **_kwargs):
            raise TypeError("foreign decode must not run")

    assert isinstance(carrier(ExplodingBytes(payload_bytes)), carrier)


def test_d336_journal_from_bytes_copies_foreign_bytes_before_checks() -> None:
    class ExplodingEnvelopeBytes(bytes):
        def endswith(self, *_args, **_kwargs):
            raise RuntimeError("foreign endswith must not run")

        def count(self, *_args, **_kwargs):
            raise RuntimeError("foreign count must not run")

    payload = _d332_payload()
    raw = runtime_lifecycle.D320CutoverJournalV1.from_payload(payload).to_bytes()

    assert (
        runtime_lifecycle.D320CutoverJournalV1.from_bytes(
            ExplodingEnvelopeBytes(raw)
        ).payload
        == payload
    )


@pytest.mark.parametrize(
    ("factory", "first", "second", "field", "view"),
    (
        (
            runtime_lifecycle.EvidenceBlobV1.from_mapping,
            _d332_blob("first"),
            _d332_blob("second"),
            "kind",
            lambda carrier: carrier.to_mapping(),
        ),
        (
            runtime_lifecycle.ByteSnapshotV1.from_mapping,
            _d332_snapshot("pointer", b"first"),
            _d332_snapshot("pointer", b"second"),
            "sha256",
            lambda carrier: carrier.to_mapping(),
        ),
        (
            runtime_lifecycle.TransitionV1.from_mapping,
            {
                "sequence": 1,
                "from": "ABSENT",
                "to": "PREFLIGHTED",
                "at_unix_ms": 1,
                "reason_code": "first",
            },
            {
                "sequence": 1,
                "from": "ABSENT",
                "to": "PREFLIGHTED",
                "at_unix_ms": 1,
                "reason_code": "second",
            },
            "reason_code",
            lambda carrier: carrier.to_mapping(),
        ),
        (
            runtime_lifecycle.StepV1.from_mapping,
            {**_d332_step(status="INTENT", inverse=False), "operation": "first"},
            {**_d332_step(status="INTENT", inverse=False), "operation": "second"},
            "operation",
            lambda carrier: carrier.to_mapping(),
        ),
        (
            runtime_lifecycle.D320CutoverJournalV1.from_payload,
            {**_d332_payload(), "journal_id": "first-journal"},
            {**_d332_payload(), "journal_id": "second-journal"},
            "journal_id",
            lambda carrier: carrier.payload,
        ),
    ),
)
def test_d336_mapping_factories_keep_the_first_split_truth(
    factory,
    first: dict[str, object],
    second: dict[str, object],
    field: str,
    view,
) -> None:
    class SplitTruthDict(dict[str, object]):
        def __init__(self) -> None:
            super().__init__(second)
            self.items_calls = 0

        def items(self):
            self.items_calls += 1
            if self.items_calls == 1:
                return first.items()
            return super().items()

    value = SplitTruthDict()
    carrier = factory(value)

    assert view(carrier)[field] == first[field]
    assert value.items_calls == 1


def test_d335_successor_rejects_cyclic_observed_artifact() -> None:
    previous_payload = _d334_normal_payload("PREFLIGHTED")
    previous = runtime_lifecycle.D320CutoverJournalV1.from_payload(previous_payload)
    successor = runtime_lifecycle.D320CutoverJournalV1.from_payload(
        _d334_blocked_successor(previous_payload, reason="unreadable")
    )
    observed = _d332_old_snapshots(previous_payload)
    cyclic: dict[str, object] = {}
    cyclic["self"] = cyclic
    observed["unit_status"] = cyclic

    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.validate_d320_journal_successor(
            previous, successor, observed=observed
        )
    assert (
        runtime_lifecycle.classify_d320_recovery(previous, observed=observed).kind
        == "UNREADABLE_BLOCKED"
    )


def test_d333_successor_is_append_only_and_phase_ordered() -> None:
    preflight = _d332_payload(state="PREFLIGHTED", sequence=1)
    intent = copy.deepcopy(preflight)
    intent["sequence"] = 2
    intent["updated_unix_ms"] = 102
    intent["steps"] = [_d332_step(status="INTENT")]
    started = copy.deepcopy(intent)
    started["sequence"] = 3
    started["updated_unix_ms"] = 103
    started["steps"][0] = _d332_step(status="EFFECT_STARTED")
    verified = copy.deepcopy(started)
    verified["sequence"] = 4
    verified["updated_unix_ms"] = 104
    verified["steps"][0] = _d332_step(status="VERIFIED")
    transitioned = copy.deepcopy(verified)
    transitioned["sequence"] = 5
    transitioned["updated_unix_ms"] = 105
    transitioned["state"] = "ROOT_ABI_VERIFIED"
    transitioned["history"].append(
        {
            "sequence": 5,
            "from": "PREFLIGHTED",
            "to": "ROOT_ABI_VERIFIED",
            "at_unix_ms": 105,
            "reason_code": "transition",
        }
    )
    journals = [
        runtime_lifecycle.D320CutoverJournalV1.from_payload(value)
        for value in (preflight, intent, started, verified, transitioned)
    ]
    for previous, successor in zip(journals, journals[1:]):
        runtime_lifecycle.validate_d320_journal_successor(previous, successor)

    skipped = copy.deepcopy(intent)
    skipped["sequence"] = 3
    skipped["updated_unix_ms"] = 103
    skipped["steps"][0] = _d332_step(status="VERIFIED")
    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.validate_d320_journal_successor(
            journals[1],
            runtime_lifecycle.D320CutoverJournalV1.from_payload(skipped),
        )
    rewritten = copy.deepcopy(intent)
    rewritten["sequence"] = 3
    rewritten["updated_unix_ms"] = 103
    rewritten["history"][0]["reason_code"] = "rewritten"
    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.validate_d320_journal_successor(
            journals[1],
            runtime_lifecycle.D320CutoverJournalV1.from_payload(rewritten),
        )

    premature_next = copy.deepcopy(started)
    premature_next["sequence"] = 4
    premature_next["updated_unix_ms"] = 104
    premature_next["steps"].append(_d332_step(index=1, status="INTENT"))
    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.validate_d320_journal_successor(
            journals[2],
            runtime_lifecycle.D320CutoverJournalV1.from_payload(premature_next),
        )
    simultaneous_transition = copy.deepcopy(started)
    simultaneous_transition["sequence"] = 4
    simultaneous_transition["updated_unix_ms"] = 104
    simultaneous_transition["steps"][0] = _d332_step(status="VERIFIED")
    simultaneous_transition["state"] = "ROOT_ABI_VERIFIED"
    simultaneous_transition["history"].append(
        {
            "sequence": 4,
            "from": "PREFLIGHTED",
            "to": "ROOT_ABI_VERIFIED",
            "at_unix_ms": 104,
            "reason_code": "transition",
        }
    )
    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.validate_d320_journal_successor(
            journals[2],
            runtime_lifecycle.D320CutoverJournalV1.from_payload(
                simultaneous_transition
            ),
        )


@pytest.mark.parametrize(
    ("before_status", "next_status", "skipped_status", "state"),
    (
        ("INTENT", "EFFECT_STARTED", "VERIFIED", "PREFLIGHTED"),
        ("VERIFIED", "INVERSE_INTENT", "INVERSE_VERIFIED", "ABORTING"),
    ),
)
def test_d333_successor_rejects_each_skipped_step_phase(
    before_status: str,
    next_status: str,
    skipped_status: str,
    state: str,
) -> None:
    payload = (
        _d332_payload_with_history(("PREFLIGHTED", "ABORTING"))
        if state == "ABORTING"
        else _d332_payload(state=state, sequence=1)
    )
    payload["steps"] = [_d332_step(status=before_status)]
    next_payload = copy.deepcopy(payload)
    next_payload["sequence"] = int(payload["sequence"]) + 1
    next_payload["updated_unix_ms"] = int(payload["updated_unix_ms"]) + 1
    next_payload["steps"][0] = _d332_step(status=next_status)
    previous = runtime_lifecycle.D320CutoverJournalV1.from_payload(payload)
    valid_next = runtime_lifecycle.D320CutoverJournalV1.from_payload(next_payload)
    runtime_lifecycle.validate_d320_journal_successor(previous, valid_next)

    skipped = copy.deepcopy(next_payload)
    skipped["steps"][0] = _d332_step(status=skipped_status)

    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.validate_d320_journal_successor(
            previous,
            runtime_lifecycle.D320CutoverJournalV1.from_payload(skipped),
        )


@pytest.mark.parametrize(
    "field",
    (
        "operation",
        "preconditions",
        "intent_unix_ms",
        "effect_started_unix_ms",
        "inverse",
    ),
)
def test_d334_repair3_successor_preserves_every_persisted_forward_field(
    field: str,
) -> None:
    started = _d332_payload(state="PREFLIGHTED", sequence=1)
    started["steps"] = [_d332_step(status="EFFECT_STARTED")]
    verified = copy.deepcopy(started)
    verified["sequence"] = 2
    verified["updated_unix_ms"] = 102
    verified["steps"][0] = _d332_step(status="VERIFIED")
    previous = runtime_lifecycle.D320CutoverJournalV1.from_payload(started)
    valid_successor = runtime_lifecycle.D320CutoverJournalV1.from_payload(verified)
    runtime_lifecycle.validate_d320_journal_successor(previous, valid_successor)

    rewritten = copy.deepcopy(verified)
    replacements: dict[str, object] = {
        "operation": "rewritten-operation",
        "preconditions": _d332_blob("preconditions", b"rewritten"),
        "intent_unix_ms": 20,
        "effect_started_unix_ms": 20,
        "inverse": _d332_blob("inverse", b"rewritten"),
    }
    rewritten["steps"][0][field] = replacements[field]
    if field == "effect_started_unix_ms":
        rewritten["steps"][0]["effect_ended_unix_ms"] = 21

    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.validate_d320_journal_successor(
            previous,
            runtime_lifecycle.D320CutoverJournalV1.from_payload(rewritten),
        )


def test_d335_index_is_rejected_before_the_successor_validator() -> None:
    started = _d332_payload(state="PREFLIGHTED", sequence=1)
    started["steps"] = [_d332_step(status="EFFECT_STARTED")]
    verified = copy.deepcopy(started)
    verified["sequence"] = 2
    verified["updated_unix_ms"] = 102
    verified["steps"][0] = _d332_step(status="VERIFIED")
    previous = runtime_lifecycle.D320CutoverJournalV1.from_payload(started)
    valid_successor = runtime_lifecycle.D320CutoverJournalV1.from_payload(verified)
    runtime_lifecycle.validate_d320_journal_successor(previous, valid_successor)

    invalid_record = copy.deepcopy(verified)
    invalid_record["steps"][0]["index"] = 1
    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.D320CutoverJournalV1.from_payload(invalid_record)


def test_d334_repair3_successor_rejects_cleared_persisted_forward_evidence() -> None:
    started = _d332_payload(state="PREFLIGHTED", sequence=1)
    started["steps"] = [_d332_step(status="EFFECT_STARTED")]
    verified = copy.deepcopy(started)
    verified["sequence"] = 2
    verified["updated_unix_ms"] = 102
    verified["steps"][0] = _d332_step(status="VERIFIED")
    previous = runtime_lifecycle.D320CutoverJournalV1.from_payload(started)

    cleared_inverse = copy.deepcopy(verified)
    cleared_inverse["steps"][0]["inverse"] = None
    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.validate_d320_journal_successor(
            previous,
            runtime_lifecycle.D320CutoverJournalV1.from_payload(cleared_inverse),
        )
    cleared_start = copy.deepcopy(verified)
    cleared_start["steps"][0]["effect_started_unix_ms"] = None
    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.D320CutoverJournalV1.from_payload(cleared_start)


def test_d334_repair3_inverse_phase_preserves_forward_evidence() -> None:
    rollback = _d332_payload_with_history(("PREFLIGHTED", "ABORTING"))
    rollback["steps"] = [_d332_step(status="VERIFIED")]
    inverse_intent = copy.deepcopy(rollback)
    inverse_intent["sequence"] = 3
    inverse_intent["updated_unix_ms"] = 103
    inverse_intent["steps"][0] = _d332_step(status="INVERSE_INTENT")
    previous = runtime_lifecycle.D320CutoverJournalV1.from_payload(rollback)
    valid_successor = runtime_lifecycle.D320CutoverJournalV1.from_payload(
        inverse_intent
    )
    runtime_lifecycle.validate_d320_journal_successor(previous, valid_successor)

    rewritten = copy.deepcopy(inverse_intent)
    rewritten["steps"][0]["effect_started_unix_ms"] = 20
    rewritten["steps"][0]["effect_ended_unix_ms"] = 21
    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.validate_d320_journal_successor(
            previous,
            runtime_lifecycle.D320CutoverJournalV1.from_payload(rewritten),
        )


def test_d337_inverse_intent_fills_only_previously_absent_inverse_evidence() -> None:
    rollback = _d332_payload_with_history(("PREFLIGHTED", "ABORTING"))
    rollback["steps"] = [_d332_step(status="VERIFIED", inverse=False)]
    inverse_intent = copy.deepcopy(rollback)
    inverse_intent["sequence"] = 3
    inverse_intent["updated_unix_ms"] = 103
    inverse_intent["steps"][0] = _d332_step(status="INVERSE_INTENT")
    previous = runtime_lifecycle.D320CutoverJournalV1.from_payload(rollback)
    valid_successor = runtime_lifecycle.D320CutoverJournalV1.from_payload(
        inverse_intent
    )
    runtime_lifecycle.validate_d320_journal_successor(previous, valid_successor)

    rewritten = copy.deepcopy(inverse_intent)
    rewritten["steps"][0]["operation"] = "rewritten-operation"
    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.validate_d320_journal_successor(
            previous,
            runtime_lifecycle.D320CutoverJournalV1.from_payload(rewritten),
        )


def test_d333_rollback_inverts_only_the_last_uninverted_step() -> None:
    rollback = _d332_payload_with_history(("PREFLIGHTED", "ABORTING"))
    rollback["steps"] = [_d332_step(index=0), _d332_step(index=1)]
    first_inverse = copy.deepcopy(rollback)
    first_inverse["sequence"] = 3
    first_inverse["updated_unix_ms"] = 103
    first_inverse["steps"][1] = _d332_step(index=1, status="INVERSE_INTENT")
    first_inverse_verified = copy.deepcopy(first_inverse)
    first_inverse_verified["sequence"] = 4
    first_inverse_verified["updated_unix_ms"] = 104
    first_inverse_verified["steps"][1] = _d332_step(index=1, status="INVERSE_VERIFIED")
    second_inverse = copy.deepcopy(first_inverse_verified)
    second_inverse["sequence"] = 5
    second_inverse["updated_unix_ms"] = 105
    second_inverse["steps"][0] = _d332_step(index=0, status="INVERSE_INTENT")
    second_inverse_verified = copy.deepcopy(second_inverse)
    second_inverse_verified["sequence"] = 6
    second_inverse_verified["updated_unix_ms"] = 106
    second_inverse_verified["steps"][0] = _d332_step(index=0, status="INVERSE_VERIFIED")
    rolled_back = copy.deepcopy(second_inverse_verified)
    rolled_back["sequence"] = 7
    rolled_back["updated_unix_ms"] = 107
    rolled_back["state"] = "ROLLED_BACK"
    rolled_back["history"].append(
        {
            "sequence": 7,
            "from": "ABORTING",
            "to": "ROLLED_BACK",
            "at_unix_ms": 107,
            "reason_code": "rollback",
        }
    )
    rolled_back["lock_trace"] = _d333_lock_trace("ROLLED_BACK", 7)
    journals = [
        runtime_lifecycle.D320CutoverJournalV1.from_payload(value)
        for value in (
            rollback,
            first_inverse,
            first_inverse_verified,
            second_inverse,
            second_inverse_verified,
            rolled_back,
        )
    ]
    for previous, successor in zip(journals, journals[1:]):
        runtime_lifecycle.validate_d320_journal_successor(previous, successor)

    out_of_order = copy.deepcopy(rollback)
    out_of_order["sequence"] = 3
    out_of_order["updated_unix_ms"] = 103
    out_of_order["steps"][0] = _d332_step(index=0, status="INVERSE_INTENT")
    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.validate_d320_journal_successor(
            journals[0],
            runtime_lifecycle.D320CutoverJournalV1.from_payload(out_of_order),
        )


@pytest.mark.parametrize(
    "state",
    runtime_lifecycle._D320_NORMAL_STATES[:-1],
)
def test_d333_every_nonterminal_aborts_to_rolled_back(state: str) -> None:
    abort = {
        "sequence": 1,
        "from": state,
        "to": "ABORTING",
        "at_unix_ms": 1,
        "reason_code": "abort",
    }
    rolled_back = {
        "sequence": 2,
        "from": "ABORTING",
        "to": "ROLLED_BACK",
        "at_unix_ms": 2,
        "reason_code": "rollback",
    }
    runtime_lifecycle.TransitionV1.from_mapping(abort)
    runtime_lifecycle.TransitionV1.from_mapping(rolled_back)


@pytest.mark.parametrize(
    "reason",
    ("unreadable", "mixed_without_complete_inverse", "noninvertible"),
)
def test_d333_aborting_blocked_requires_a_bound_reason(reason: str) -> None:
    transition = {
        "sequence": 1,
        "from": "ABORTING",
        "to": "BLOCKED",
        "at_unix_ms": 1,
        "reason_code": reason,
    }
    runtime_lifecycle.TransitionV1.from_mapping(transition)
    transition["reason_code"] = "arbitrary"
    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.TransitionV1.from_mapping(transition)


@pytest.mark.parametrize("state", runtime_lifecycle._D320_NORMAL_STATES[:-1])
@pytest.mark.parametrize(
    ("kind", "reason"),
    (
        ("UNREADABLE_BLOCKED", "unreadable"),
        ("MIXED_BLOCKED", "mixed_without_complete_inverse"),
        ("NONINVERTIBLE_BLOCKED", "noninvertible"),
    ),
)
def test_d334_each_nonlive_normal_state_blocks_only_with_bound_evidence(
    state: str, kind: str, reason: str
) -> None:
    previous_payload = _d334_normal_payload(state)
    if kind == "NONINVERTIBLE_BLOCKED" and previous_payload["steps"]:
        previous_payload["steps"][0]["inverse"] = None
    previous = runtime_lifecycle.D320CutoverJournalV1.from_payload(previous_payload)
    successor_payload = _d334_blocked_successor(previous_payload, reason=reason)
    successor = runtime_lifecycle.D320CutoverJournalV1.from_payload(successor_payload)
    observed = _d332_old_snapshots(previous_payload)
    if kind == "UNREADABLE_BLOCKED":
        observed["unit_status"] = {"invalid": None}
    elif kind == "MIXED_BLOCKED":
        observed["pointer"] = runtime_lifecycle.ByteSnapshotV1.from_mapping(
            _d332_snapshot("pointer", b"neither-old-nor-new")
        )
    else:
        observed["pointer"] = _d332_new_snapshots(previous_payload)["pointer"]

    runtime_lifecycle.validate_d320_journal_successor(
        previous, successor, observed=observed
    )


def test_d334_live_granted_cannot_transition_to_blocked() -> None:
    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.TransitionV1.from_mapping(
            {
                "sequence": 1,
                "from": "LIVE_GRANTED",
                "to": "BLOCKED",
                "at_unix_ms": 1,
                "reason_code": "noninvertible",
            }
        )


@pytest.mark.parametrize("state", runtime_lifecycle._D320_NORMAL_STATES[:-1])
def test_d334_repair3_each_direct_normal_blocked_transition_rejects_arbitrary_reason(
    state: str,
) -> None:
    transition = {
        "sequence": 1,
        "from": state,
        "to": "BLOCKED",
        "at_unix_ms": 1,
        "reason_code": "arbitrary",
    }
    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.TransitionV1.from_mapping(transition)

    payload = _d334_normal_payload(state)
    blocked = _d334_blocked_successor(payload, reason="arbitrary")
    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.D320CutoverJournalV1.from_payload(blocked)


def test_d334_repair3_aborting_blocked_rejects_bad_reason() -> None:
    payload = _d332_payload_with_history(("PREFLIGHTED", "ABORTING"))
    blocked = _d334_blocked_successor(payload, reason="arbitrary")

    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.D320CutoverJournalV1.from_payload(blocked)


@pytest.mark.parametrize(
    ("kind", "reason"),
    (
        ("UNREADABLE_BLOCKED", "unreadable"),
        ("MIXED_BLOCKED", "mixed_without_complete_inverse"),
        ("NONINVERTIBLE_BLOCKED", "noninvertible"),
    ),
)
def test_d334_aborting_blocked_requires_the_matching_recovery_kind(
    kind: str, reason: str
) -> None:
    previous_payload = _d332_payload_with_history(("PREFLIGHTED", "ABORTING"))
    previous = runtime_lifecycle.D320CutoverJournalV1.from_payload(previous_payload)
    successor = runtime_lifecycle.D320CutoverJournalV1.from_payload(
        _d334_blocked_successor(previous_payload, reason=reason)
    )
    observed = _d332_old_snapshots(previous_payload)
    if kind == "UNREADABLE_BLOCKED":
        observed["unit_status"] = {"invalid": None}
    elif kind == "MIXED_BLOCKED":
        observed["pointer"] = runtime_lifecycle.ByteSnapshotV1.from_mapping(
            _d332_snapshot("pointer", b"neither-old-nor-new")
        )
    else:
        observed["pointer"] = _d332_new_snapshots(previous_payload)["pointer"]

    runtime_lifecycle.validate_d320_journal_successor(
        previous, successor, observed=observed
    )


def test_d334_block_evidence_is_required_and_exclusive() -> None:
    aborting = _d332_payload_with_history(("PREFLIGHTED", "ABORTING"))
    previous = runtime_lifecycle.D320CutoverJournalV1.from_payload(aborting)
    blocked = runtime_lifecycle.D320CutoverJournalV1.from_payload(
        _d334_blocked_successor(aborting, reason="noninvertible")
    )
    observed = _d332_old_snapshots(aborting)
    observed["pointer"] = _d332_new_snapshots(aborting)["pointer"]

    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.validate_d320_journal_successor(previous, blocked)
    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.validate_d320_journal_successor(
            previous, blocked, observed=_d332_old_snapshots(aborting)
        )
    mismatched = _d332_old_snapshots(aborting)
    mismatched["pointer"] = runtime_lifecycle.ByteSnapshotV1.from_mapping(
        _d332_snapshot("pointer", b"neither-old-nor-new")
    )
    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.validate_d320_journal_successor(
            previous, blocked, observed=mismatched
        )

    preflight = _d332_payload(state="PREFLIGHTED", sequence=1)
    next_payload = _d332_payload(state="ROOT_ABI_VERIFIED", sequence=2)
    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.validate_d320_journal_successor(
            runtime_lifecycle.D320CutoverJournalV1.from_payload(preflight),
            runtime_lifecycle.D320CutoverJournalV1.from_payload(next_payload),
            observed=observed,
        )


def test_d334_step_phases_are_bound_to_rollback_states() -> None:
    normal = _d332_payload(
        state="USER_CUTOVER_IN_PROGRESS",
        sequence=6,
        steps=[_d332_step(status="INVERSE_INTENT")],
    )
    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.D320CutoverJournalV1.from_payload(normal)

    aborting = _d332_payload_with_history(("PREFLIGHTED", "ABORTING"))
    aborting["steps"] = [
        _d332_step(index=0, status="VERIFIED"),
        _d332_step(index=1, status="INVERSE_INTENT"),
        _d332_step(index=2, status="INVERSE_VERIFIED"),
    ]
    runtime_lifecycle.D320CutoverJournalV1.from_payload(aborting)
    blocked = _d334_blocked_successor(aborting, reason="mixed_without_complete_inverse")
    runtime_lifecycle.D320CutoverJournalV1.from_payload(blocked)

    malformed = copy.deepcopy(aborting)
    malformed["steps"][0] = _d332_step(index=0, status="EFFECT_STARTED")
    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.D320CutoverJournalV1.from_payload(malformed)

    rolled_back = _d332_payload_with_history(("PREFLIGHTED", "ABORTING", "ROLLED_BACK"))
    rolled_back["steps"] = [_d332_step(status="INVERSE_VERIFIED")]
    runtime_lifecycle.D320CutoverJournalV1.from_payload(rolled_back)
    rolled_back["steps"][0] = _d332_step(status="VERIFIED")
    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.D320CutoverJournalV1.from_payload(rolled_back)


def test_d334_rejects_an_effectless_cutover_record() -> None:
    payload = _d332_payload()
    payload["postcutover"] = copy.deepcopy(payload["precutover"])

    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.D320CutoverJournalV1.from_payload(payload)


def test_d334_lock_events_bind_to_history_and_current_terminal_record() -> None:
    payload = _d332_payload_with_history(("PREFLIGHTED", "ABORTING", "ROLLED_BACK"))
    runtime_lifecycle.D320CutoverJournalV1.from_payload(payload)
    history = payload["history"]
    assert isinstance(history, list)
    trace = payload["lock_trace"]
    assert isinstance(trace, list)
    runtime_lifecycle.validate_d324_lock_order(
        trace,
        state="ROLLED_BACK",
        sequence=3,
        history=history,
    )

    unknown_state = copy.deepcopy(payload)
    unknown_state["lock_trace"][0]["state"] = "ROOT_ABI_VERIFIED"
    above_record = copy.deepcopy(payload)
    above_record["lock_trace"][0]["sequence"] = 4
    foreign_terminal = copy.deepcopy(payload)
    foreign_terminal["lock_trace"][-1]["state"] = "LIVE_GRANTED"
    old_terminal = copy.deepcopy(payload)
    old_terminal["lock_trace"][-1]["sequence"] = 2
    for invalid in (unknown_state, above_record, foreign_terminal, old_terminal):
        with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
            runtime_lifecycle.D320CutoverJournalV1.from_payload(invalid)

    reversed_trace = _d333_complete_lock_trace()
    reversed_trace[1]["sequence"] = 1
    reversed_trace[1]["state"] = "ABORTING"
    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.validate_d324_lock_order(
            reversed_trace,
            state="ROLLED_BACK",
            sequence=3,
            history=_d332_history_for_states(
                ("PREFLIGHTED", "ABORTING", "ROLLED_BACK")
            ),
        )


def test_d333_digest_precedes_payload_semantics() -> None:
    journal = runtime_lifecycle.D320CutoverJournalV1.from_payload(_d332_payload())
    payload_bytes = journal.payload_bytes.replace(b'"sequence":0', b'"sequence":true')
    raw = b'{"content_sha256":"' + b"0" * 64 + b'","payload":' + payload_bytes + b"}\n"

    with pytest.raises(runtime_lifecycle.D320CutoverJournalError) as raised:
        runtime_lifecycle.D320CutoverJournalV1.from_bytes(raw)
    assert raised.value.args == ("d320_envelope_digest_invalid",)


def test_d335_digest_precedes_finite_float_semantics() -> None:
    float_payload = b'{"sequence":1.0}'
    raw = b'{"content_sha256":"' + b"0" * 64 + b'","payload":' + float_payload + b"}\n"

    with pytest.raises(runtime_lifecycle.D320CutoverJournalError) as raised:
        runtime_lifecycle.D320CutoverJournalV1.from_bytes(raw)
    assert raised.value.args == ("d320_envelope_digest_invalid",)


def test_d335_single_record_rejects_nonterminal_predecessor_step() -> None:
    payload = _d332_payload(state="PREFLIGHTED", sequence=1)
    payload["steps"] = [
        _d332_step(index=0, status="INTENT"),
        _d332_step(index=1, status="INTENT"),
    ]

    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.D320CutoverJournalV1.from_payload(payload)


def test_d335_record_generation_binds_history_and_appended_lockevents() -> None:
    previous_payload = _d332_payload(state="PREFLIGHTED", sequence=1)
    previous = runtime_lifecycle.D320CutoverJournalV1.from_payload(previous_payload)
    successor_payload = copy.deepcopy(previous_payload)
    successor_payload["sequence"] = 2
    successor_payload["updated_unix_ms"] = 102
    successor_payload["state"] = "ROOT_ABI_VERIFIED"
    successor_payload["history"].append(
        {
            "sequence": 2,
            "from": "PREFLIGHTED",
            "to": "ROOT_ABI_VERIFIED",
            "at_unix_ms": 102,
            "reason_code": "transition",
        }
    )
    successor_payload["lock_trace"].append(
        {
            "event": "ACQUIRE",
            "lock": "Lifecycle-Lock",
            "state": "ROOT_ABI_VERIFIED",
            "sequence": 2,
        }
    )
    successor = runtime_lifecycle.D320CutoverJournalV1.from_payload(successor_payload)
    runtime_lifecycle.validate_d320_journal_successor(previous, successor)

    stale_lockevent = copy.deepcopy(successor_payload)
    stale_lockevent["lock_trace"][-1].update({"state": "PREFLIGHTED", "sequence": 1})
    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.validate_d320_journal_successor(
            previous,
            runtime_lifecycle.D320CutoverJournalV1.from_payload(stale_lockevent),
        )

    skewed_record = copy.deepcopy(previous_payload)
    skewed_record["sequence"] = 99
    skewed_record["updated_unix_ms"] = 199
    skewed_record["history"][0]["sequence"] = 0
    skewed_record["lock_trace"][0]["sequence"] = 0
    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.D320CutoverJournalV1.from_payload(skewed_record)


def test_d335_observed_shape_stops_after_one_surplus_key() -> None:
    class OverlongObservedMapping(Mapping[str, object]):
        def __init__(self) -> None:
            self.key_visits = 0

        def __len__(self) -> int:
            return len(runtime_lifecycle._D320_ARTIFACT_NAMES)

        def __iter__(self):
            for name in runtime_lifecycle._D320_ARTIFACT_NAMES:
                self.key_visits += 1
                yield name
            for index in range(65_537 - len(runtime_lifecycle._D320_ARTIFACT_NAMES)):
                self.key_visits += 1
                yield f"surplus-{index}"

        def __getitem__(self, key: str) -> object:
            raise KeyError(key)

    observed = OverlongObservedMapping()
    journal = runtime_lifecycle.D320CutoverJournalV1.from_payload(_d332_payload())
    assert (
        runtime_lifecycle.classify_d320_recovery(journal, observed=observed).kind
        == "UNREADABLE_BLOCKED"
    )
    assert observed.key_visits == len(runtime_lifecycle._D320_ARTIFACT_NAMES) + 1


@pytest.mark.parametrize(
    "mutation",
    (
        lambda trace: trace.pop(),
        lambda trace: trace.__setitem__(
            1,
            {
                "event": "RELEASE",
                "lock": "D324-Journallock",
                "state": "PREFLIGHTED",
                "sequence": 1,
            },
        ),
        lambda trace: trace.append(
            {
                "event": "ACQUIRE",
                "lock": "D324-Journallock",
                "state": "PREFLIGHTED",
                "sequence": 3,
            }
        ),
    ),
)
def test_d333_lock_trace_rejects_early_release_reacquire_and_missing_hold(
    mutation,
) -> None:
    trace = _d333_complete_lock_trace()
    history = _d332_history_for_states(("PREFLIGHTED", "ABORTING", "ROLLED_BACK"))
    runtime_lifecycle.validate_d324_lock_order(
        trace, state="ROLLED_BACK", sequence=3, history=history
    )
    mutation(trace)

    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.validate_d324_lock_order(
            trace, state="ROLLED_BACK", sequence=3, history=history
        )


@pytest.mark.parametrize("lock", runtime_lifecycle.D324_LOCK_ORDER[1:])
def test_d335_each_sublock_release_and_reacquire_is_rejected(lock: str) -> None:
    history = _d332_history_for_states(("PREFLIGHTED", "ABORTING", "ROLLED_BACK"))
    journal_acquire = {
        "event": "ACQUIRE",
        "lock": "D324-Journallock",
        "state": "PREFLIGHTED",
        "sequence": 1,
    }
    lock_acquire = {
        "event": "ACQUIRE",
        "lock": lock,
        "state": "PREFLIGHTED",
        "sequence": 1,
    }
    lock_release = {
        "event": "RELEASE",
        "lock": lock,
        "state": "PREFLIGHTED",
        "sequence": 1,
    }
    journal_release = {
        "event": "RELEASE",
        "lock": "D324-Journallock",
        "state": "ROLLED_BACK",
        "sequence": 3,
    }
    reference = [journal_acquire, lock_acquire, lock_release, journal_release]
    runtime_lifecycle.validate_d324_lock_order(
        reference, state="ROLLED_BACK", sequence=3, history=history
    )

    reacquired = [
        journal_acquire,
        lock_acquire,
        lock_release,
        lock_acquire,
        lock_release,
        journal_release,
    ]
    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.validate_d324_lock_order(
            reacquired, state="ROLLED_BACK", sequence=3, history=history
        )


def test_d335_lock_trace_rejects_later_acquire_after_sublock_release() -> None:
    history = _d332_history_for_states(("PREFLIGHTED", "ABORTING", "ROLLED_BACK"))
    journal = {
        "event": "ACQUIRE",
        "lock": "D324-Journallock",
        "state": "PREFLIGHTED",
        "sequence": 1,
    }
    lifecycle = {
        "event": "ACQUIRE",
        "lock": "Lifecycle-Lock",
        "state": "PREFLIGHTED",
        "sequence": 1,
    }
    lifecycle_release = {**lifecycle, "event": "RELEASE"}
    journal_release = {
        "event": "RELEASE",
        "lock": "D324-Journallock",
        "state": "ROLLED_BACK",
        "sequence": 3,
    }
    reference = [journal, lifecycle, lifecycle_release, journal_release]
    runtime_lifecycle.validate_d324_lock_order(
        reference, state="ROLLED_BACK", sequence=3, history=history
    )

    rootexecutor = {
        "event": "ACQUIRE",
        "lock": "Rootexecutor-Lock",
        "state": "PREFLIGHTED",
        "sequence": 1,
    }
    nonreverse = [
        journal,
        lifecycle,
        lifecycle_release,
        rootexecutor,
        {**rootexecutor, "event": "RELEASE"},
        journal_release,
    ]
    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.validate_d324_lock_order(
            nonreverse, state="ROLLED_BACK", sequence=3, history=history
        )


def test_d335_step_and_history_times_are_record_bound() -> None:
    reversed_step = _d332_step(status="EFFECT_STARTED")
    reversed_step["effect_started_unix_ms"] = 10
    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.StepV1.from_mapping(reversed_step)

    future_step = _d332_payload(state="PREFLIGHTED", sequence=1)
    future_step["steps"] = [_d332_step(status="INTENT")]
    future_step["steps"][0]["intent_unix_ms"] = 102
    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.D320CutoverJournalV1.from_payload(future_step)

    payload = _d332_payload(state="ROOT_ABI_VERIFIED", sequence=2)
    payload["history"][1]["at_unix_ms"] = 99
    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.D320CutoverJournalV1.from_payload(payload)


def _runtime_v2_payload(home: Path) -> dict[str, object]:
    home.mkdir(mode=0o700)
    target = home.stat()
    commit = "a" * 40
    stage_name = ".the-hive-runtime.stage.fixture"
    absent = {
        "type": "absent",
        "dev": None,
        "ino": None,
        "uid": None,
        "gid": None,
        "mode": None,
        "nlink": None,
        "children": [],
    }
    files = [
        {
            "name": Path(relative).name,
            "path": str(home / relative),
            "present": False,
            "bytes_b64": None,
            "sha256": None,
            "dev": None,
            "ino": None,
            "uid": None,
            "gid": None,
            "mode": None,
            "nlink": None,
            "size": None,
        }
        for relative in runtime_lifecycle._V2_FILE_PATHS
    ]
    effects = [
        {
            "kind": kind,
            "path": path,
            "present": False,
            "identity": dict(absent),
        }
        for path, kind in runtime_lifecycle._v2_expected_effects(
            home, commit, stage_name
        ).items()
    ]
    manager = {
        unit: {
            "LoadState": "loaded",
            "UnitFileState": "disabled",
            "ActiveState": "inactive",
        }
        for unit in runtime_lifecycle._V2_MANAGER_UNITS
    }
    target_binding = {
        "realpath": str(home.resolve()),
        "dev": target.st_dev,
        "ino": target.st_ino,
        "uid": target.st_uid,
        "gid": target.st_gid,
        "mode": target.st_mode & 0o777,
    }
    predecessor = {
        "generation": "e" * 40,
        "manifest_digest": "sha256:" + "f" * 64,
        "consumer_pin": True,
        "consumer_sha256": "1" * 64,
    }
    plan = {
        "schema": "D320RuntimeCutoverPlanV2",
        "mode": "runtime_lifecycle",
        "source": {"commit": commit, "tree_sha256": "d" * 64},
        "target": target_binding,
        "owner_uid": target.st_uid,
        "predecessor": predecessor,
        "compatibility": {"status": "qualified", "sha256": "2" * 64},
        "qualification": {
            "status": "qualified",
            "issued_at_unix_ns": 1,
            "sha256": "3" * 64,
        },
        "files": [
            {key: item[key] for key in ("name", "path", "present")} for item in files
        ],
        "extra_effects": runtime_lifecycle._v2_plan_effects(home, commit),
        "manager_states": manager,
        "actions": ["install", "activate", "observe", "commit"],
        "inverse_actions": ["restore_manager", "restore_files", "discard_generation"],
        "output_manifest_digest": "pending",
    }
    plan_sha256 = hashlib.sha256(
        runtime_lifecycle._d320_canonical_json(plan)
    ).hexdigest()
    return {
        "schema": "D320CutoverJournalV2",
        "mode": "runtime_lifecycle",
        "journal_id": "journal-fixture-1",
        "transaction_id": 1,
        "lock_generation": 1,
        "sequence": 1,
        "phase": "INTENT",
        "plan_sha256": plan_sha256,
        "plan": plan,
        "source": {"commit": commit, "tree_sha256": "d" * 64},
        "target": target_binding,
        "owner_uid": target.st_uid,
        "predecessor": {
            "generation": "e" * 40,
            "manifest_digest": "sha256:" + "f" * 64,
            "consumer_sha256": "1" * 64,
        },
        "stage_name": stage_name,
        "files": files,
        "extra_effects": effects,
        "manager_pre": manager,
        "inverse_actions": [
            "restore_manager",
            "restore_files",
            "discard_generation",
        ],
        "sealed": None,
        "post": None,
        "recovery_count": 0,
        "steps": [
            {
                "sequence": 1,
                "phase": "INTENT",
                "action": "intent_persisted",
                "effect": next(
                    effect["path"] for effect in effects if effect["kind"] == "journal"
                ),
                "sha256": plan_sha256,
            }
        ],
    }


@pytest.mark.parametrize(
    ("field", "invalid_value"),
    (
        ("post", {"files": [{"path": "/unbound/foreign"}]}),
        ("steps", [{"phase": "COMMITTED", "path": "/unbound/foreign"}]),
    ),
)
def test_runtime_lifecycle_v2_rejects_unbound_post_and_step_evidence(
    tmp_path: Path, field: str, invalid_value: object
) -> None:
    payload = _runtime_v2_payload(tmp_path / field)
    payload[field] = invalid_value

    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.D320CutoverJournalV2.from_payload(payload)


def test_runtime_lifecycle_v2_intent_round_trips_without_v1_fallback(
    tmp_path: Path,
) -> None:
    journal = runtime_lifecycle.D320CutoverJournalV2.from_payload(
        _runtime_v2_payload(tmp_path / "roundtrip")
    )
    raw = journal.to_bytes()

    assert (
        runtime_lifecycle.D320CutoverJournalV2.from_bytes(raw).payload
        == journal.payload
    )
    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.D320CutoverJournalV1.from_bytes(raw)


@pytest.mark.parametrize("decoder", ("from_payload", "from_bytes"))
def test_runtime_lifecycle_v2_rejects_fixture_only_qualification(
    tmp_path: Path, decoder: str
) -> None:
    payload = _runtime_v2_payload(tmp_path / decoder)
    payload["plan"]["qualification"] = {"status": "test_fixture_only"}
    payload["plan_sha256"] = hashlib.sha256(
        runtime_lifecycle._d320_canonical_json(payload["plan"])
    ).hexdigest()
    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        if decoder == "from_payload":
            runtime_lifecycle.D320CutoverJournalV2.from_payload(payload)
        else:
            raw = runtime_lifecycle._d320_journal_envelope(
                runtime_lifecycle._d320_canonical_json(payload)
            )
            runtime_lifecycle.D320CutoverJournalV2.from_bytes(raw)


def test_public_resume_requires_current_qualification_record(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "resume-home"
    payload = _runtime_v2_payload(home)
    _lifecycle_state(home)
    runtime_lifecycle._v2_journal_path(home).write_bytes(
        runtime_lifecycle._d320_journal_envelope(
            runtime_lifecycle._d320_canonical_json(payload)
        )
    )
    runtime_lifecycle._v2_journal_path(home).chmod(0o600)
    qualification_root = tmp_path / "missing-qualification-root"
    monkeypatch.setattr(
        runtime_lifecycle, "_canary_runtime_root", lambda: qualification_root
    )
    phase_calls: list[str] = []
    monkeypatch.setattr(
        runtime_lifecycle,
        "_v2_phase_plan",
        lambda **_kwargs: phase_calls.append("phase") or {"status": "ready"},
    )

    result = runtime_lifecycle.plan(home=home, systemctl=lambda _args: {})

    assert result["status"] == "runtime_lifecycle_plan_blocked"
    assert "runtime_lifecycle_qualification_record_missing" in result["reason_codes"]
    assert phase_calls == []
    assert not qualification_root.exists()


def test_public_plan_accepts_current_owner_qualified_structural_profile(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pinned_client_digest = _bind_test_codex_client(monkeypatch)
    fixture_bound, _fixture_states = _bound_failure_fixture(tmp_path)
    source_root = tmp_path / "owner-source"
    source_root.mkdir(mode=0o700)
    installer_source = ROOT / "scripts" / "the-hive-hive-hourly-probe-install"
    installer = runpy.run_path(str(installer_source))
    for source_name, _target_name, _mode in installer["_RUNTIME_IMAGE_FILES"]:
        source = ROOT / source_name
        target = source_root / source_name
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        shutil.copy2(source, target)
    for source_name, target_name in installer["_RUNTIME_IMAGE_TREES"]:
        shutil.copytree(ROOT / source_name, source_root / target_name)
    private_installer_source = (
        source_root / "scripts" / "the-hive-hive-hourly-probe-install"
    )
    private_installer_source.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    shutil.copy2(installer_source, private_installer_source)
    git_home = tmp_path / "git-home"
    git_home.mkdir(mode=0o700)
    git_env = {
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "HOME": str(git_home),
        "LANG": "C",
        "PATH": "/usr/bin:/bin",
    }
    subprocess.run(
        ["git", "-C", str(source_root), "init", "--quiet", "--initial-branch=main"],
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=git_env,
    )
    subprocess.run(
        ["git", "-C", str(source_root), "add", "--all"],
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=git_env,
    )
    subprocess.run(
        [
            "git",
            "-C",
            str(source_root),
            "-c",
            "user.name=Private Fixture",
            "-c",
            "user.email=private-fixture@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "core.hooksPath=/dev/null",
            "commit",
            "--quiet",
            "-m",
            "private owner fixture",
        ],
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=git_env,
    )
    monkeypatch.setattr(
        runtime_lifecycle,
        "__file__",
        str(source_root / "src" / "the_hive" / "runtime_lifecycle.py"),
    )
    profile = (
        source_root
        / "src"
        / "the_hive"
        / "markdown"
        / "runtime-release-compatibility-v1.json"
    )
    raw_profile = profile.read_bytes()
    profile_digest = hashlib.sha256(raw_profile).hexdigest()
    source_commit, source_tree = runtime_lifecycle._source_tree_binding(source_root)
    assert (
        subprocess.run(
            ["git", "-C", str(source_root), "status", "--porcelain=v1"],
            check=True,
            capture_output=True,
            env=git_env,
        ).stdout
        == b""
    )
    release_root = fixture_bound.release_root
    (release_root / ".the-hive-release-pointers.json").unlink()
    HookSessionPinStoreV1.create_at(
        fixture_bound.home / ".local" / "state" / "the-hive" / "hook-session-pins-v1"
    )
    predecessor_stage = tmp_path / "predecessor-stage"
    predecessor_stage.mkdir(mode=0o700)
    with runtime_lifecycle._bound_installer_entry(source_root) as entry:
        private_installer = runpy.run_path(f"/proc/self/fd/{entry.descriptor}")
        private_installer["_build_runtime_image"](
            repository=source_root,
            stage=predecessor_stage,
            generation="e" * 40,
            commit=source_commit,
        )
        private_installer["_publish_runtime_generation"](
            stage=predecessor_stage,
            release_root=release_root,
        )
    predecessor = runtime_lifecycle._runtime_identity(release_root)
    assert isinstance(predecessor, Mapping) and predecessor["consumer_pin"] is True
    runtime_lifecycle._revalidate_v2_predecessor(release_root, predecessor)
    bound = runtime_lifecycle._bind_cutover_inputs(fixture_bound.home)
    assert (bound.source_commit, bound.source_tree_digest) == (
        source_commit,
        source_tree,
    )
    qualification_root = tmp_path / "qualification-owner"
    monkeypatch.setattr(
        runtime_lifecycle, "_canary_runtime_root", lambda: qualification_root
    )
    prepared_images: list[runtime_lifecycle._CanaryImage] = []
    prepare_canary_image = runtime_lifecycle._prepare_canary_image

    def capture_canary_image(**kwargs: object) -> runtime_lifecycle._CanaryImage:
        image = prepare_canary_image(**kwargs)
        prepared_images.append(image)
        return image

    monkeypatch.setattr(
        runtime_lifecycle, "_prepare_canary_image", capture_canary_image
    )
    transient_manager = _CanaryManager(success=True)
    manager_observations: list[str] = []

    def private_systemctl(arguments: tuple[str, ...]) -> dict[str, str]:
        if (
            arguments[0] == "show"
            and arguments[1] in runtime_lifecycle._V2_MANAGER_UNITS
        ):
            unit = arguments[1]
            manager_observations.append(unit)
            unit_path = fixture_bound.units / unit
            try:
                info = unit_path.lstat()
            except FileNotFoundError:
                return {
                    "LoadState": "not-found",
                    "UnitFileState": "",
                    "ActiveState": "inactive",
                    "Result": "success",
                    "ExecMainStatus": "0",
                }
            assert stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid()
            return {
                "LoadState": "loaded",
                "UnitFileState": "disabled",
                "ActiveState": "inactive",
                "Result": "success",
                "ExecMainStatus": "0",
            }
        return transient_manager.systemctl(arguments)

    def private_systemd_run(arguments: tuple[str, ...]) -> dict[str, str]:
        result = transient_manager.run(arguments)
        assert len(prepared_images) == 1
        health = prepared_images[0].state_root / "hive-hourly-health.json"
        assert not health.exists()
        health.write_bytes(_canary_green_health())
        health.chmod(0o600)
        return result

    canary_result = runtime_lifecycle.canary(
        home=bound.home,
        systemctl=private_systemctl,
        systemd_run=private_systemd_run,
    )
    assert canary_result["status"] == "runtime_canary_green", canary_result
    assert set(manager_observations) == set(runtime_lifecycle._V2_MANAGER_UNITS)
    record = runtime_lifecycle._read_canary_qualification_record(qualification_root)
    if isinstance(record, Mapping):
        bindings = record.get("bindings")
        criteria = record.get("criteria")
        bindings = bindings if isinstance(bindings, Mapping) else {}
        criteria = criteria if isinstance(criteria, Mapping) else {}
        client = bindings.get("client")
        client = client if isinstance(client, Mapping) else {}
        compatibility = client.get("compatibility_probe")
        compatibility = compatibility if isinstance(compatibility, Mapping) else {}
        manager = bindings.get("manager_api_contract")
        manager = manager if isinstance(manager, Mapping) else {}
        manager_details = manager.get("manager")
        manager_details = (
            manager_details if isinstance(manager_details, Mapping) else {}
        )
        predecessor = bindings.get("predecessor")
        predecessor = predecessor if isinstance(predecessor, Mapping) else {}
        diagnostic = {
            "record_status": record.get("status"),
            "criteria": {
                key: criteria.get(key)
                for key in sorted(runtime_lifecycle._CANARY_QUALIFICATION_CRITERIA)
            },
            "bindings": {
                "source_commit": bindings.get("source_commit"),
                "source_tree_sha256": bindings.get("source_tree_sha256"),
                "candidate_generation": bindings.get("candidate_generation"),
                "candidate_manifest_digest": bindings.get("candidate_manifest_digest"),
                "profile_sha256": bindings.get("profile_sha256"),
                "manager_states_sha256": bindings.get("manager_states_sha256"),
                "predecessor": {
                    key: predecessor.get(key)
                    for key in ("generation", "manifest_digest", "consumer_sha256")
                },
                "client": {
                    key: client.get(key)
                    for key in ("artifact_sha256", "features_sha256", "version")
                },
                "client_compatibility_probe": {
                    key: compatibility.get(key)
                    for key in (
                        "schema_revision",
                        "argv",
                        "exit_codes",
                        "expected",
                        "observed",
                        "config_sha256",
                        "readback_line_sha256",
                        "response_sha256",
                    )
                },
                "manager_api_contract": {
                    "api_sha256": manager.get("api_sha256"),
                    "unit_path_sha256": manager.get("unit_path_sha256"),
                    "manager": {
                        key: manager_details.get(key)
                        for key in ("version", "features_sha256")
                    },
                    "present": bool(manager),
                },
            },
        }
        print(
            "CANARY_QUALIFICATION_DIAGNOSTIC "
            + json.dumps(diagnostic, sort_keys=True, separators=(",", ":"))
        )
    assert isinstance(record, Mapping) and record["status"] == "qualified"
    assert record["criteria"]["runtime_canary"] == "pass"
    assert record["criteria"]["runtime_features"] == "pass"
    if pinned_client_digest is not None:
        client_binding = record["bindings"]["client"]
        assert client_binding["artifact_sha256"] == pinned_client_digest
        assert client_binding["version"] == "codex-cli 0.161.0"

    def reject_client_exec(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("public plan attempted client execution")

    def reject_temp_home(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("public plan attempted temporary home creation")

    monkeypatch.setattr(
        runtime_lifecycle, "_run_pinned_client_command", reject_client_exec
    )
    monkeypatch.setattr(
        runtime_lifecycle.tempfile, "TemporaryDirectory", reject_temp_home
    )

    result = runtime_lifecycle.plan(
        home=bound.home,
        systemctl=private_systemctl,
    )

    assert result["status"] == "runtime_lifecycle_plan_ready", result
    assert result["reason_codes"] == []
    assert result["plan"]["compatibility"] == {
        "status": "qualified",
        "sha256": profile_digest,
    }
    monkeypatch.setattr(
        runtime_lifecycle, "_canonical_codex_client_digest", lambda: "e" * 64
    )
    changed = runtime_lifecycle.plan(
        home=bound.home,
        systemctl=private_systemctl,
    )
    assert changed["status"] == "runtime_lifecycle_plan_blocked", changed
    assert "runtime_lifecycle_qualification_record_changed" in changed["reason_codes"]


def test_public_recover_rejects_persisted_fixture_only_qualification(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "recover-home"
    payload = _runtime_v2_payload(home)
    payload["plan"]["qualification"] = {"status": "test_fixture_only"}
    payload["plan_sha256"] = hashlib.sha256(
        runtime_lifecycle._d320_canonical_json(payload["plan"])
    ).hexdigest()
    _lifecycle_state(home)
    path = runtime_lifecycle._v2_journal_path(home)
    path.write_bytes(
        runtime_lifecycle._d320_journal_envelope(
            runtime_lifecycle._d320_canonical_json(payload)
        )
    )
    path.chmod(0o600)
    recovery_calls: list[str] = []
    monkeypatch.setattr(
        runtime_lifecycle,
        "_v2_recover_phase",
        lambda **_kwargs: recovery_calls.append("recover") or {"status": "recovered"},
    )

    result = runtime_lifecycle.cutover(
        home=home,
        plan_sha256=payload["plan_sha256"],
        phase="recover",
        systemctl=lambda _args: {},
    )

    assert result["status"] == "runtime_lifecycle_journal_invalid"
    assert recovery_calls == []
    assert path.exists()


@pytest.mark.parametrize(
    ("change", "reason"),
    (
        ("expired", "runtime_lifecycle_qualification_record_expired"),
        ("binding", "runtime_lifecycle_qualification_record_changed"),
        ("profile_binding", "runtime_lifecycle_qualification_record_changed"),
        ("client_binding", "runtime_lifecycle_qualification_record_changed"),
        ("target_binding", "runtime_lifecycle_qualification_record_changed"),
        ("manager_binding", "runtime_lifecycle_qualification_record_changed"),
        ("manager_api_binding", "runtime_lifecycle_qualification_record_changed"),
        ("manager_actions_unknown", ""),
        ("client_behavior_unknown", ""),
        (
            "client_compatibility_unknown",
            "runtime_lifecycle_qualification_record_unverified",
        ),
    ),
)
def test_public_resume_rebinds_qualification_record(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    change: str,
    reason: str,
) -> None:
    home = tmp_path / change
    payload = _runtime_v2_payload(home)
    source = payload["plan"]["source"]
    predecessor = payload["plan"]["predecessor"]
    compatibility = payload["plan"]["compatibility"]
    issued_at = time.time_ns()
    client_metadata = _client_metadata_fixture()
    monkeypatch.setattr(
        runtime_lifecycle,
        "_canary_client_metadata",
        lambda _invocation: client_metadata,
    )
    monkeypatch.setattr(
        runtime_lifecycle, "_canonical_codex_client_digest", lambda: "a" * 64
    )
    current_manager_contract = _manager_api_contract_fixture()
    if change == "manager_api_binding":
        current_manager_contract = dict(current_manager_contract)
        current_manager_contract["api_sha256"] = "e" * 64
    monkeypatch.setattr(
        runtime_lifecycle,
        "_manager_api_contract_snapshot",
        lambda: current_manager_contract,
    )
    if change == "expired":
        issued_at -= runtime_lifecycle._OWNER_RECEIPT_FRESHNESS_NS + 1
    record = {
        "bindings": {
            "candidate_generation": source["commit"],
            "candidate_manifest_digest": "sha256:" + "a" * 64,
            "client": _client_metadata_fixture(),
            "manager_states_sha256": hashlib.sha256(
                runtime_lifecycle._d320_canonical_json(
                    payload["plan"]["manager_states"]
                )
            ).hexdigest(),
            "manager_api_contract": _manager_api_contract_fixture(),
            "predecessor": {
                key: predecessor[key]
                for key in ("consumer_sha256", "generation", "manifest_digest")
            },
            "profile_sha256": compatibility["sha256"],
            "source_commit": source["commit"],
            "source_tree_sha256": source["tree_sha256"],
            "target": dict(payload["plan"]["target"]),
        },
        "criteria": {
            "client_behavior": (
                "unknown"
                if change in {"manager_actions_unknown", "client_behavior_unknown"}
                else "pass"
            ),
            "client_probe": "pass",
            "client_compatibility": (
                "unknown" if change == "client_compatibility_unknown" else "pass"
            ),
            "manager_api_contract": "pass",
            "manager_actions": "unknown",
            "runtime_canary": "pass",
            "runtime_features": "pass",
        },
        "issued_at_unix_ns": issued_at,
        "owner_uid": os.geteuid(),
        "schema_version": 1,
        "status": "qualified",
    }
    if change == "binding":
        record["bindings"]["source_commit"] = "f" * 40
    elif change == "profile_binding":
        record["bindings"]["profile_sha256"] = "f" * 64
    elif change == "client_binding":
        record["bindings"]["client"]["artifact_sha256"] = "f" * 64
    elif change == "target_binding":
        payload["plan"]["target"]["ino"] += 1
        payload["target"] = dict(payload["plan"]["target"])
    elif change == "manager_binding":
        payload["plan"]["manager_states"][runtime_lifecycle._NEW_TIMER][
            "ActiveState"
        ] = "active"
        payload["manager_pre"] = dict(payload["plan"]["manager_states"])
    payload["plan"]["qualification"] = {
        "status": "qualified",
        "issued_at_unix_ns": issued_at,
        "sha256": hashlib.sha256(
            runtime_lifecycle._d320_canonical_json(record)
        ).hexdigest(),
    }
    payload["plan_sha256"] = hashlib.sha256(
        runtime_lifecycle._d320_canonical_json(payload["plan"])
    ).hexdigest()
    _lifecycle_state(home)
    path = runtime_lifecycle._v2_journal_path(home)
    path.write_bytes(
        runtime_lifecycle._d320_journal_envelope(
            runtime_lifecycle._d320_canonical_json(payload)
        )
    )
    path.chmod(0o600)
    monkeypatch.setattr(
        runtime_lifecycle, "_read_canary_qualification_record", lambda _root: record
    )
    phase_calls: list[str] = []
    monkeypatch.setattr(
        runtime_lifecycle,
        "_v2_phase_plan",
        lambda **_kwargs: phase_calls.append("phase") or {"status": "ready"},
    )

    result = runtime_lifecycle.plan(home=home, systemctl=lambda _args: {})

    if change in {"manager_actions_unknown", "client_behavior_unknown"}:
        assert result == {"status": "ready"}
        assert phase_calls == ["phase"]
        assert path.exists()
        return
    assert result["status"] == "runtime_lifecycle_plan_blocked"
    assert result["reason_codes"] == [reason]
    assert phase_calls == []
    assert path.exists()


def test_public_recovery_does_not_require_unexpired_forward_qualification(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "recovery-home"
    payload = _runtime_v2_payload(home)
    _lifecycle_state(home)
    path = runtime_lifecycle._v2_journal_path(home)
    path.write_bytes(
        runtime_lifecycle._d320_journal_envelope(
            runtime_lifecycle._d320_canonical_json(payload)
        )
    )
    path.chmod(0o600)
    recovery_calls: list[str] = []
    monkeypatch.setattr(
        runtime_lifecycle,
        "_v2_recover_phase",
        lambda **_kwargs: (
            recovery_calls.append("recover")
            or {"status": "runtime_lifecycle_recovery_complete"}
        ),
    )

    result = runtime_lifecycle.cutover(
        home=home,
        plan_sha256=payload["plan_sha256"],
        phase="recover",
        systemctl=lambda _args: {},
    )

    assert result["status"] == "runtime_lifecycle_recovery_complete"
    assert recovery_calls == ["recover"]
    assert path.exists()


@pytest.mark.parametrize("decoder", ("from_payload", "from_bytes"))
@pytest.mark.parametrize(
    "invalid_compatibility",
    (
        {"status": "test_fixture_only", "sha256": "2" * 64},
        {"status": "present_unvalidated", "sha256": "2" * 64},
        {"status": "qualified", "sha256": "2" * 64, "extra": "field"},
    ),
)
def test_runtime_lifecycle_v2_rejects_unqualified_compatibility(
    tmp_path: Path, decoder: str, invalid_compatibility: dict[str, str]
) -> None:
    payload = _runtime_v2_payload(tmp_path / decoder)
    payload["plan"]["compatibility"] = invalid_compatibility
    payload["plan_sha256"] = hashlib.sha256(
        runtime_lifecycle._d320_canonical_json(payload["plan"])
    ).hexdigest()

    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        if decoder == "from_payload":
            runtime_lifecycle.D320CutoverJournalV2.from_payload(payload)
        else:
            raw = runtime_lifecycle._d320_journal_envelope(
                runtime_lifecycle._d320_canonical_json(payload)
            )
            runtime_lifecycle.D320CutoverJournalV2.from_bytes(raw)


def test_public_resume_rejects_persisted_fixture_only_compatibility(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "compatibility-resume-home"
    payload = _runtime_v2_payload(home)
    compatibility_sha = payload["plan"]["compatibility"]["sha256"]
    payload["plan"]["compatibility"] = {
        "status": "test_fixture_only",
        "sha256": compatibility_sha,
    }
    record = {
        "bindings": {
            "candidate_generation": payload["plan"]["source"]["commit"],
            "candidate_manifest_digest": "sha256:" + "a" * 64,
            "client": _client_metadata_fixture(),
            "manager_states_sha256": hashlib.sha256(
                runtime_lifecycle._d320_canonical_json(
                    payload["plan"]["manager_states"]
                )
            ).hexdigest(),
            "manager_api_contract": _manager_api_contract_fixture(),
            "predecessor": {
                key: payload["plan"]["predecessor"][key]
                for key in ("consumer_sha256", "generation", "manifest_digest")
            },
            "profile_sha256": compatibility_sha,
            "source_commit": payload["plan"]["source"]["commit"],
            "source_tree_sha256": payload["plan"]["source"]["tree_sha256"],
            "target": dict(payload["plan"]["target"]),
        },
        "criteria": {
            "client_behavior": "pass",
            "client_probe": "pass",
            "client_compatibility": "pass",
            "manager_api_contract": "pass",
            "manager_actions": "unknown",
            "runtime_canary": "pass",
            "runtime_features": "pass",
        },
        "issued_at_unix_ns": 1,
        "owner_uid": os.geteuid(),
        "schema_version": 1,
        "status": "qualified",
    }
    payload["plan"]["qualification"] = {
        "status": "qualified",
        "issued_at_unix_ns": 1,
        "sha256": hashlib.sha256(
            runtime_lifecycle._d320_canonical_json(record)
        ).hexdigest(),
    }
    payload["plan_sha256"] = hashlib.sha256(
        runtime_lifecycle._d320_canonical_json(payload["plan"])
    ).hexdigest()
    _lifecycle_state(home)
    journal_path = runtime_lifecycle._v2_journal_path(home)
    journal_path.write_bytes(
        runtime_lifecycle._d320_journal_envelope(
            runtime_lifecycle._d320_canonical_json(payload)
        )
    )
    journal_path.chmod(0o600)
    monkeypatch.setattr(
        runtime_lifecycle, "_read_canary_qualification_record", lambda _root: record
    )
    monkeypatch.setattr(runtime_lifecycle.time, "time_ns", lambda: 2)
    phase_calls: list[str] = []
    monkeypatch.setattr(
        runtime_lifecycle,
        "_v2_phase_plan",
        lambda **_kwargs: phase_calls.append("phase") or {"status": "ready"},
    )

    result = runtime_lifecycle.plan(home=home, systemctl=lambda _args: {})

    assert result["status"] == "runtime_lifecycle_journal_invalid"
    assert phase_calls == []
    assert journal_path.exists()


def test_public_recover_rejects_persisted_fixture_only_compatibility(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "compatibility-recover-home"
    payload = _runtime_v2_payload(home)
    payload["plan"]["compatibility"]["status"] = "test_fixture_only"
    payload["plan_sha256"] = hashlib.sha256(
        runtime_lifecycle._d320_canonical_json(payload["plan"])
    ).hexdigest()
    _lifecycle_state(home)
    journal_path = runtime_lifecycle._v2_journal_path(home)
    journal_path.write_bytes(
        runtime_lifecycle._d320_journal_envelope(
            runtime_lifecycle._d320_canonical_json(payload)
        )
    )
    journal_path.chmod(0o600)
    recovery_calls: list[str] = []
    monkeypatch.setattr(
        runtime_lifecycle,
        "_v2_recover_phase",
        lambda **_kwargs: recovery_calls.append("recover") or {"status": "recovered"},
    )

    result = runtime_lifecycle.cutover(
        home=home,
        plan_sha256=payload["plan_sha256"],
        phase="recover",
        systemctl=lambda _args: {},
    )

    assert result["status"] == "runtime_lifecycle_journal_invalid"
    assert recovery_calls == []
    assert journal_path.exists()


def test_runtime_lifecycle_v2_store_uses_digest_fenced_atomic_successors(
    tmp_path: Path,
) -> None:
    home = tmp_path / "store-home"
    first = runtime_lifecycle.D320CutoverJournalV2.from_payload(
        _runtime_v2_payload(home)
    )
    _lifecycle_state(home)

    with runtime_lifecycle._lifecycle_lock(home) as lease:
        runtime_lifecycle._v2_store_journal(
            home, first, expected_digest=None, lease=lease
        )

    path = runtime_lifecycle._v2_journal_path(home)
    assert runtime_lifecycle._v2_load_journal(home) == first
    assert path.stat().st_mode & 0o777 == 0o600
    assert path.stat().st_nlink == 1
    next_payload = first.payload
    next_payload["sequence"] = 2
    next_payload["phase"] = "BLOCKED"
    next_payload["steps"].append(
        {
            "sequence": 2,
            "phase": "BLOCKED",
            "action": "blocked",
            "effect": str(path),
            "sha256": "2" * 64,
        }
    )
    successor = runtime_lifecycle.D320CutoverJournalV2.from_payload(next_payload)
    current_digest = hashlib.sha256(first.to_bytes()).hexdigest()
    with runtime_lifecycle._lifecycle_lock(home) as lease:
        with pytest.raises(
            runtime_lifecycle.RuntimeLifecycleError,
            match="^runtime_lifecycle_journal_changed$",
        ):
            runtime_lifecycle._v2_store_journal(
                home, successor, expected_digest="0" * 64, lease=lease
            )
    assert runtime_lifecycle._v2_load_journal(home) == first

    with runtime_lifecycle._lifecycle_lock(home) as lease:
        runtime_lifecycle._v2_store_journal(
            home,
            successor,
            expected_digest=current_digest,
            previous=first,
            lease=lease,
        )
    assert runtime_lifecycle._v2_load_journal(home) == successor


def test_runtime_lifecycle_v2_store_serializes_stale_writers_across_processes(
    tmp_path: Path,
) -> None:
    home = tmp_path / "multiprocess-home"
    initial = runtime_lifecycle.D320CutoverJournalV2.from_payload(
        _runtime_v2_payload(home)
    )
    _lifecycle_state(home)
    with runtime_lifecycle._lifecycle_lock(home) as lease:
        runtime_lifecycle._v2_store_journal(
            home, initial, expected_digest=None, lease=lease
        )
    next_payload = initial.payload
    next_payload["sequence"] = 2
    next_payload["phase"] = "BLOCKED"
    next_payload["steps"].append(
        {
            "sequence": 2,
            "phase": "BLOCKED",
            "action": "blocked",
            "effect": str(runtime_lifecycle._v2_journal_path(home)),
            "sha256": "2" * 64,
        }
    )
    successor = runtime_lifecycle.D320CutoverJournalV2.from_payload(next_payload)
    expected = hashlib.sha256(initial.to_bytes()).hexdigest()
    context = multiprocessing.get_context("fork")
    start = context.Event()
    results = context.Queue()

    def writer() -> None:
        start.wait()
        for _attempt in range(100):
            try:
                with runtime_lifecycle._lifecycle_lock(home) as lease:
                    runtime_lifecycle._v2_store_journal(
                        home,
                        successor,
                        expected_digest=expected,
                        previous=initial,
                        lease=lease,
                    )
            except runtime_lifecycle.RuntimeLifecycleError as exc:
                if str(exc) == "runtime_lifecycle_busy":
                    time.sleep(0.01)
                    continue
                results.put(str(exc))
            else:
                results.put("written")
            return
        results.put("runtime_lifecycle_busy")

    writers = [context.Process(target=writer) for _ in range(2)]
    for process in writers:
        process.start()
    start.set()
    for process in writers:
        process.join(timeout=10)
        assert process.exitcode == 0
    outcomes = sorted([results.get(timeout=2), results.get(timeout=2)])
    assert outcomes == ["runtime_lifecycle_journal_changed", "written"]
    assert runtime_lifecycle._v2_load_journal(home) == successor


@pytest.mark.parametrize("hive_exists", [False, True])
def test_runtime_lifecycle_v2_bootstrap_recovers_first_lock_creation(
    tmp_path: Path, hive_exists: bool
) -> None:
    home = tmp_path / ("first-home-hive" if hive_exists else "first-home-clean")
    home.mkdir(mode=0o700)
    state_parent = home / ".local" / "state" / "codex-master-mcp"
    for directory in (
        home / ".local",
        home / ".local" / "state",
        state_parent,
    ):
        directory.mkdir(mode=0o700)
        directory.chmod(0o700)
    if hive_exists:
        (state_parent / "hive").mkdir(mode=0o700)

    runtime_lifecycle._v2_bootstrap_store(home)

    lock = state_parent / "hive" / ".runtime-lifecycle.lock"
    assert lock.is_file() and lock.stat().st_mode & 0o777 == 0o600
    assert lock.stat().st_nlink == 1
    assert runtime_lifecycle._v2_load_journal(home) is None
    assert not (home / ".local" / "lib").exists()
    assert not (home / ".config" / "systemd" / "user").exists()


def test_public_recover_holds_on_unjournaled_file_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "recover-drift-home"
    payload = _runtime_v2_payload(home)
    _lifecycle_state(home)
    monkeypatch.setattr(
        runtime_lifecycle,
        "_source_tree_binding",
        lambda _repository: ("a" * 40, "d" * 64),
    )
    monkeypatch.setattr(runtime_lifecycle, "_source_digest", lambda _path: "c" * 64)
    states = {
        unit: {
            "LoadState": "loaded",
            "UnitFileState": "disabled",
            "ActiveState": "inactive",
        }
        for unit in runtime_lifecycle._V2_MANAGER_UNITS
    }

    def systemctl(arguments: tuple[str, ...]) -> dict[str, str]:
        if arguments[0] == "show":
            return states[arguments[1]]
        return {}

    journal = runtime_lifecycle.D320CutoverJournalV2.from_payload(payload)
    with runtime_lifecycle._lifecycle_lock(home) as lease:
        runtime_lifecycle._v2_store_journal(
            home, journal, expected_digest=None, lease=lease
        )
    snapshot = payload["files"][0]
    changed_path = Path(snapshot["path"])
    changed_path.parent.mkdir(mode=0o700, parents=True)
    changed_path.write_bytes(b"unrecorded change\n")
    recorded_journal_bytes = runtime_lifecycle._v2_journal_path(home).read_bytes()

    result = runtime_lifecycle.cutover(
        home=home,
        plan_sha256=journal.payload["plan_sha256"],
        phase="recover",
        systemctl=systemctl,
    )

    assert result["status"] == "runtime_lifecycle_recovery_hold", result
    assert (
        runtime_lifecycle._v2_journal_path(home).read_bytes() == recorded_journal_bytes
    )
    assert changed_path.read_bytes() == b"unrecorded change\n"


def test_public_recover_holds_on_same_bytes_replaced_inode(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "recover-inode-home"
    payload = _runtime_v2_payload(home)
    _lifecycle_state(home)
    snapshot = payload["files"][0]
    path = Path(snapshot["path"])
    path.parent.mkdir(mode=0o700, parents=True)
    for directory in (home / ".local", home / ".local/lib", path.parent):
        directory.chmod(0o700)
    original = b'{"schema_version":1,"current":null,"previous":null}\n'
    path.write_bytes(original)
    path.chmod(0o644)
    info = path.lstat()
    snapshot.update(
        present=True,
        bytes_b64=base64.b64encode(original).decode("ascii"),
        sha256=hashlib.sha256(original).hexdigest(),
        dev=info.st_dev,
        ino=info.st_ino,
        uid=info.st_uid,
        gid=info.st_gid,
        mode=0o644,
        nlink=info.st_nlink,
        size=len(original),
    )
    payload["plan"]["files"][0].update(
        present=True,
        sha256=snapshot["sha256"],
        mode=0o644,
        dev=info.st_dev,
        ino=info.st_ino,
        uid=info.st_uid,
        gid=info.st_gid,
        nlink=info.st_nlink,
    )
    payload["plan_sha256"] = hashlib.sha256(
        runtime_lifecycle._d320_canonical_json(payload["plan"])
    ).hexdigest()
    payload["steps"][0]["sha256"] = payload["plan_sha256"]
    payload["extra_effects"] = runtime_lifecycle._v2_capture_effects(
        home, payload["source"]["commit"], payload["stage_name"]
    )
    journal = runtime_lifecycle.D320CutoverJournalV2.from_payload(payload)
    with runtime_lifecycle._lifecycle_lock(home) as lease:
        runtime_lifecycle._v2_store_journal(
            home, journal, expected_digest=None, lease=lease
        )
    _replace_file_with_live_inode(path, original, 0o644)
    monkeypatch.setattr(
        runtime_lifecycle,
        "_source_tree_binding",
        lambda _repository: ("a" * 40, "d" * 64),
    )
    monkeypatch.setattr(runtime_lifecycle, "_source_digest", lambda _path: "c" * 64)

    states = payload["manager_pre"]

    def systemctl(arguments: tuple[str, ...]) -> dict[str, str]:
        if arguments[0] == "show":
            return states[arguments[1]]
        return {}

    result = runtime_lifecycle.cutover(
        home=home,
        plan_sha256=journal.payload["plan_sha256"],
        phase="recover",
        systemctl=systemctl,
    )
    assert result["status"] == "runtime_lifecycle_recovery_hold", result
    assert path.read_bytes() == original
    assert runtime_lifecycle._v2_load_journal(home).payload["phase"] == "INTENT"


def test_v2_file_snapshot_identity_rejects_same_bytes_with_another_inode(
    tmp_path: Path,
) -> None:
    path = tmp_path / "attested-file"
    content = b"same content, different physical object\n"
    path.write_bytes(content)
    path.chmod(0o644)
    before = path.lstat()
    snapshot = {
        "present": True,
        "dev": before.st_dev,
        "ino": before.st_ino,
        "uid": before.st_uid,
        "gid": before.st_gid,
        "mode": 0o644,
        "nlink": before.st_nlink,
        "size": before.st_size,
    }
    assert runtime_lifecycle._v2_file_snapshot_identity_matches(path, snapshot)

    replacement = _replace_file_with_live_inode(path, content, 0o644)
    assert (replacement.st_dev, replacement.st_ino) != (before.st_dev, before.st_ino)
    assert not runtime_lifecycle._v2_file_snapshot_identity_matches(path, snapshot)


def test_public_recover_does_not_remove_unbound_preexisting_stage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "recover-stage-home"
    payload = _runtime_v2_payload(home)
    _lifecycle_state(home)
    library = home / ".local/lib"
    library.mkdir(mode=0o700, parents=True)
    (home / ".local").chmod(0o700)
    library.chmod(0o700)
    stage = library / payload["stage_name"]
    stage.mkdir(mode=0o700)
    marker = stage / "foreign-marker"
    marker.write_bytes(b"retain me\n")
    marker.chmod(0o600)
    payload["extra_effects"] = runtime_lifecycle._v2_capture_effects(
        home, payload["source"]["commit"], payload["stage_name"]
    )
    journal = runtime_lifecycle.D320CutoverJournalV2.from_payload(payload)
    with runtime_lifecycle._lifecycle_lock(home) as lease:
        runtime_lifecycle._v2_store_journal(
            home, journal, expected_digest=None, lease=lease
        )
    monkeypatch.setattr(
        runtime_lifecycle,
        "_source_tree_binding",
        lambda _repository: ("a" * 40, "d" * 64),
    )
    monkeypatch.setattr(runtime_lifecycle, "_source_digest", lambda _path: "c" * 64)

    states = payload["manager_pre"]

    def systemctl(arguments: tuple[str, ...]) -> dict[str, str]:
        if arguments[0] == "show":
            return states[arguments[1]]
        return {}

    result = runtime_lifecycle.cutover(
        home=home,
        plan_sha256=journal.payload["plan_sha256"],
        phase="recover",
        systemctl=systemctl,
    )
    assert result["status"] == "runtime_lifecycle_recovery_hold", result
    assert marker.read_bytes() == b"retain me\n"
    assert runtime_lifecycle._v2_journal_path(home).read_bytes() == journal.to_bytes()


@pytest.mark.parametrize("replace_with_foreign_inode", [False, True])
def test_public_recover_sealed_stage_requires_reserved_physical_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    replace_with_foreign_inode: bool,
) -> None:
    home, payload, journal, stage, generation, installer = _sealed_v2_recovery_fixture(
        tmp_path / "sealed", published=False
    )
    if replace_with_foreign_inode:
        replacement = stage.with_name(stage.name + ".replacement")
        shutil.copytree(stage, replacement)
        original_inode = stage.lstat().st_ino
        shutil.rmtree(stage)
        replacement.rename(stage)
        assert stage.lstat().st_ino != original_inode
        from the_hive.runtime_layout import RuntimeLayout

        assert (
            RuntimeLayout.from_runtime_root(stage).manifest_digest
            == payload["sealed"]["manifest_digest"]
        )
    stage_inode = stage.lstat().st_ino
    _patch_recovery_runtime_validation(monkeypatch, installer)
    _patch_recovery_bindings(monkeypatch)

    result = runtime_lifecycle.cutover(
        home=home,
        plan_sha256=journal.payload["plan_sha256"],
        phase="recover",
        systemctl=_recovery_systemctl(payload),
    )

    if replace_with_foreign_inode:
        assert result["status"] == "runtime_lifecycle_recovery_hold", result
        assert stage.lstat().st_ino == stage_inode
        from the_hive.runtime_layout import RuntimeLayout

        assert (
            RuntimeLayout.from_runtime_root(stage).manifest_digest
            == payload["sealed"]["manifest_digest"]
        )
        assert runtime_lifecycle._v2_load_journal(home).payload["phase"] == "SEALED"
    else:
        assert result["status"] == "runtime_lifecycle_recovery_complete", result
        assert not stage.exists()


@pytest.mark.parametrize("replace_with_foreign_inode", [False, True])
def test_public_recover_published_generation_requires_stage_inode_binding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    replace_with_foreign_inode: bool,
) -> None:
    home, payload, journal, stage, generation, installer = _sealed_v2_recovery_fixture(
        tmp_path / "published", published=True
    )
    if replace_with_foreign_inode:
        replacement = generation.with_name(generation.name + ".replacement")
        shutil.copytree(generation, replacement)
        original_inode = generation.lstat().st_ino
        shutil.rmtree(generation)
        replacement.rename(generation)
        assert generation.lstat().st_ino != original_inode
        from the_hive.runtime_layout import RuntimeLayout

        assert (
            RuntimeLayout.from_runtime_root(generation).manifest_digest
            == payload["sealed"]["manifest_digest"]
        )
    generation_inode = generation.lstat().st_ino
    _patch_recovery_runtime_validation(monkeypatch, installer)
    _patch_recovery_bindings(
        monkeypatch,
        generation=payload["source"]["commit"],
        manifest_digest=payload["sealed"]["manifest_digest"],
    )
    result = runtime_lifecycle.cutover(
        home=home,
        plan_sha256=journal.payload["plan_sha256"],
        phase="recover",
        systemctl=_recovery_systemctl(payload),
    )

    if replace_with_foreign_inode:
        assert result["status"] == "runtime_lifecycle_recovery_hold", result
        assert generation.lstat().st_ino == generation_inode
        from the_hive.runtime_layout import RuntimeLayout

        assert (
            RuntimeLayout.from_runtime_root(generation).manifest_digest
            == payload["sealed"]["manifest_digest"]
        )
        assert runtime_lifecycle._v2_load_journal(home).payload["phase"] == "INSTALLED"
    else:
        assert result["status"] == "runtime_lifecycle_recovery_complete", result
        assert not generation.exists()


def _sealed_v2_recovery_fixture(
    root: Path, *, published: bool
) -> tuple[Path, dict[str, object], object, Path, Path, dict[str, object]]:
    home = root / "home"
    root.mkdir(mode=0o700)
    payload = _runtime_v2_payload(home)
    _lifecycle_state(home)
    library = home / ".local/lib"
    release = library / "the-hive-runtime"
    generations = release / "generations"
    library.mkdir(mode=0o700, parents=True)
    release.mkdir(mode=0o700)
    generations.mkdir(mode=0o700)
    stage = library / payload["stage_name"]
    temporary = runtime_lifecycle._v2_setup_temp_path(payload, stage)
    temporary.mkdir(mode=0o700)
    generation = generations / payload["source"]["commit"]
    installer = runpy.run_path(
        os.fspath(ROOT / "scripts" / "the-hive-hive-hourly-probe-install")
    )
    with runtime_lifecycle._lifecycle_lock(home) as lease:
        journal = runtime_lifecycle.D320CutoverJournalV2.from_payload(payload)
        runtime_lifecycle._v2_store_journal(
            home, journal, expected_digest=None, lease=lease
        )
        installer["_build_runtime_image"](
            repository=ROOT,
            stage=temporary,
            generation=payload["source"]["commit"],
            commit=payload["source"]["commit"],
        )
        reservation = runtime_lifecycle._v2_setup_reservation_digest(temporary, stage)
        journal = runtime_lifecycle._v2_transition(
            home,
            journal,
            lease=lease,
            phase="INTENT",
            action="effect_created",
            effect=str(temporary),
            digest=reservation,
        )
        os.replace(temporary, stage)
        from the_hive.runtime_layout import RuntimeLayout

        layout = RuntimeLayout.from_runtime_root(stage)
        hourly_service, hourly_timer = installer["_staged_hourly_probe_unit_bytes"](
            layout=layout, generation=payload["source"]["commit"]
        )
        pricing_service, pricing_timer = installer[
            "_staged_pricing_inventory_unit_bytes"
        ](layout=layout)
        output_bytes = {
            "mcp_launcher": installer["_attested_stable_mcp_launcher_bytes"](layout),
            "hourly_service": hourly_service,
            "hourly_timer": hourly_timer,
            "pricing_launcher": installer["_attested_pricing_inventory_launcher_bytes"](
                layout
            ),
            "pricing_service": pricing_service,
            "pricing_timer": pricing_timer,
            "legacy_launcher": installer["_attested_legacy_probe_launcher_bytes"](
                layout
            ),
        }
        sealed = {
            "generation": payload["source"]["commit"],
            "manifest_digest": layout.manifest_digest,
            "output_sha256": {
                name: hashlib.sha256(content).hexdigest()
                for name, content in output_bytes.items()
            },
            "stage_identity_sha256": runtime_lifecycle._v2_setup_reservation_digest(
                stage, stage
            ),
            "generation_identity_sha256": runtime_lifecycle._v2_setup_reservation_digest(
                stage, generation, parent_path=generation.parent
            ),
        }
        journal = runtime_lifecycle._v2_transition(
            home,
            journal,
            lease=lease,
            phase="SEALED",
            action="stage_sealed",
            effect=str(stage),
            digest=layout.manifest_digest.removeprefix("sha256:"),
            updates={"sealed": sealed},
        )
        if published:
            os.replace(stage, generation)
            journal = runtime_lifecycle._v2_transition(
                home,
                journal,
                lease=lease,
                phase="INSTALLED",
                action="generation_published",
                effect=str(generation),
                digest=layout.manifest_digest.removeprefix("sha256:"),
            )
    return home, journal.payload, journal, stage, generation, installer


def _patch_recovery_runtime_validation(
    monkeypatch: pytest.MonkeyPatch, installer: dict[str, object]
) -> None:
    installer["_validate_runtime_image_stage"] = lambda **_kwargs: None
    real_run_path = runpy.run_path

    def fixture_run_path(path: str, *args: object, **kwargs: object):
        if os.fspath(path).endswith("the-hive-hive-hourly-probe-install"):
            return installer
        return real_run_path(path, *args, **kwargs)

    monkeypatch.setattr(runtime_lifecycle.runpy, "run_path", fixture_run_path)


def _patch_recovery_bindings(
    monkeypatch: pytest.MonkeyPatch,
    *,
    generation: str | None = None,
    manifest_digest: str = "sha256:" + "0" * 64,
) -> None:
    monkeypatch.setattr(
        runtime_lifecycle,
        "_source_tree_binding",
        lambda _repository: ("a" * 40, "d" * 64),
    )
    monkeypatch.setattr(runtime_lifecycle, "_source_digest", lambda _path: "c" * 64)
    if generation is not None:
        monkeypatch.setattr(
            runtime_lifecycle,
            "_runtime_identity",
            lambda _release_root: {
                "generation": generation,
                "manifest_digest": manifest_digest,
            },
        )


def _recovery_systemctl(payload: dict[str, object]):
    states = payload["manager_pre"]

    def systemctl(arguments: tuple[str, ...]) -> dict[str, str]:
        if arguments[0] == "show":
            return states[arguments[1]]
        return {}

    return systemctl


def test_public_recover_resumes_after_own_atomic_file_restore_replace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "recover-own-restore-home"
    payload = _runtime_v2_observed_payload(home)
    _lifecycle_state(home)
    original = b'{"schema_version":1,"current":null,"previous":null}\n'
    current = b'{"schema_version":1,"current":"new","previous":null}\n'
    snapshot = payload["files"][0]
    path = Path(snapshot["path"])
    path.parent.mkdir(mode=0o700, parents=True)
    for directory in (home / ".local", home / ".local/lib", path.parent):
        directory.chmod(0o700)
    path.write_bytes(original)
    path.chmod(0o644)
    before = path.lstat()
    snapshot.update(
        present=True,
        bytes_b64=base64.b64encode(original).decode("ascii"),
        sha256=hashlib.sha256(original).hexdigest(),
        dev=before.st_dev,
        ino=before.st_ino,
        uid=before.st_uid,
        gid=before.st_gid,
        mode=0o644,
        nlink=before.st_nlink,
        size=len(original),
    )
    planned = payload["plan"]["files"][0]
    planned.update(
        present=True,
        sha256=snapshot["sha256"],
        mode=0o644,
        dev=before.st_dev,
        ino=before.st_ino,
        uid=before.st_uid,
        gid=before.st_gid,
        nlink=before.st_nlink,
    )
    payload["plan_sha256"] = hashlib.sha256(
        runtime_lifecycle._d320_canonical_json(payload["plan"])
    ).hexdigest()
    payload["steps"][0]["sha256"] = payload["plan_sha256"]

    path.write_bytes(current)
    path.chmod(0o644)
    after = path.lstat()
    post_snapshot = copy.deepcopy(snapshot)
    post_snapshot.update(
        bytes_b64=base64.b64encode(current).decode("ascii"),
        sha256=hashlib.sha256(current).hexdigest(),
        dev=after.st_dev,
        ino=after.st_ino,
        uid=after.st_uid,
        gid=after.st_gid,
        nlink=after.st_nlink,
        size=len(current),
    )
    payload["post"]["files"][0] = post_snapshot
    payload["extra_effects"] = runtime_lifecycle._v2_capture_effects(
        home, payload["source"]["commit"], payload["stage_name"]
    )
    payload["post"]["extra_effects"] = copy.deepcopy(payload["extra_effects"])
    for step in payload["steps"]:
        if step["phase"] != "OBSERVED" or step["action"] != "effect_readback":
            continue
        observed = next(
            item
            for item in payload["post"]["files"] + payload["post"]["extra_effects"]
            if item["path"] == step["effect"]
        )
        step["sha256"] = hashlib.sha256(
            runtime_lifecycle._d320_canonical_json(observed)
        ).hexdigest()
    observed_journal = runtime_lifecycle.D320CutoverJournalV2.from_payload(payload)

    initial_payload = copy.deepcopy(payload)
    initial_payload.update(phase="INTENT", sequence=1, sealed=None, post=None)
    initial_payload["steps"] = [copy.deepcopy(payload["steps"][0])]
    initial_journal = runtime_lifecycle.D320CutoverJournalV2.from_payload(
        initial_payload
    )
    with runtime_lifecycle._lifecycle_lock(home) as lease:
        runtime_lifecycle._v2_store_journal(
            home, initial_journal, expected_digest=None, lease=lease
        )
        journal = runtime_lifecycle._v2_transition(
            home,
            initial_journal,
            lease=lease,
            phase="SEALED",
            action="stage_sealed",
            effect=next(
                item["path"]
                for item in payload["extra_effects"]
                if item["kind"] == "stage"
            ),
            digest=payload["sealed"]["manifest_digest"][7:],
            updates={"sealed": payload["sealed"]},
        )
        journal = runtime_lifecycle._v2_transition(
            home,
            journal,
            lease=lease,
            phase="INSTALLED",
            action="generation_published",
            effect=next(
                item["path"]
                for item in payload["extra_effects"]
                if item["kind"] == "generation"
            ),
            digest=payload["sealed"]["manifest_digest"][7:],
        )
        journal = runtime_lifecycle._v2_transition(
            home,
            journal,
            lease=lease,
            phase="ACTIVATED",
            action="manager_mutation",
            effect="manager:" + runtime_lifecycle._NEW_TIMER,
            digest="2" * 64,
        )
        readbacks = [
            (
                "effect_readback",
                item["path"],
                hashlib.sha256(
                    runtime_lifecycle._d320_canonical_json(item)
                ).hexdigest(),
            )
            for item in payload["post"]["files"] + payload["post"]["extra_effects"]
        ] + [
            (
                "manager_readback",
                "manager:" + unit,
                hashlib.sha256(
                    runtime_lifecycle._d320_canonical_json(state)
                ).hexdigest(),
            )
            for unit, state in payload["post"]["manager_states"].items()
        ]
        first, *rest = readbacks
        runtime_lifecycle._v2_transition(
            home,
            journal,
            lease=lease,
            phase="OBSERVED",
            action=first[0],
            effect=first[1],
            digest=first[2],
            updates={"post": payload["post"]},
            additional_steps=tuple(rest),
        )

    monkeypatch.setattr(
        runtime_lifecycle,
        "_source_tree_binding",
        lambda _repository: ("a" * 40, "d" * 64),
    )
    monkeypatch.setattr(runtime_lifecycle, "_source_digest", lambda _path: "c" * 64)
    monkeypatch.setattr(
        runtime_lifecycle,
        "_runtime_identity",
        lambda _release_root: {
            "generation": observed_journal.payload["sealed"]["generation"],
            "manifest_digest": observed_journal.payload["sealed"]["manifest_digest"],
        },
    )

    def systemctl(arguments: tuple[str, ...]) -> dict[str, str]:
        return payload["manager_pre"][arguments[1]] if arguments[0] == "show" else {}

    atomic_restore = runtime_lifecycle._atomic_restore

    class SimulatedProcessDeath(BaseException):
        pass

    def die_after_replace(
        target: Path, content: bytes, mode: int, **kwargs: object
    ) -> None:
        atomic_restore(target, content, mode, **kwargs)
        if target == path:
            raise SimulatedProcessDeath

    monkeypatch.setattr(runtime_lifecycle, "_atomic_restore", die_after_replace)
    with pytest.raises(SimulatedProcessDeath):
        runtime_lifecycle.cutover(
            home=home,
            plan_sha256=observed_journal.payload["plan_sha256"],
            phase="recover",
            systemctl=systemctl,
        )
    assert path.read_bytes() == original
    assert path.lstat().st_ino != before.st_ino
    assert runtime_lifecycle._v2_load_journal(home).payload["phase"] == "RECOVERING"

    monkeypatch.setattr(runtime_lifecycle, "_atomic_restore", atomic_restore)
    resumed = runtime_lifecycle.cutover(
        home=home,
        plan_sha256=observed_journal.payload["plan_sha256"],
        phase="recover",
        systemctl=systemctl,
    )
    assert resumed["status"] == "runtime_lifecycle_recovery_complete", resumed


def test_public_recover_rolls_back_durable_intent_without_product_effects(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    home = tmp_path / "recover-home"
    payload = _runtime_v2_payload(home)
    _lifecycle_state(home)
    payload["extra_effects"] = runtime_lifecycle._v2_capture_effects(
        home, payload["source"]["commit"], payload["stage_name"]
    )
    monkeypatch.setattr(
        runtime_lifecycle,
        "_source_tree_binding",
        lambda _repository: ("a" * 40, "d" * 64),
    )
    monkeypatch.setattr(runtime_lifecycle, "_source_digest", lambda _path: "c" * 64)
    monkeypatch.setattr(
        runtime_lifecycle,
        "_runtime_identity",
        lambda _release_root: {
            "generation": "e" * 40,
            "manifest_digest": "sha256:" + "f" * 64,
            "consumer_pin": True,
            "consumer_sha256": "1" * 64,
        },
    )
    states = {
        unit: {
            "LoadState": "loaded",
            "UnitFileState": "disabled",
            "ActiveState": "inactive",
        }
        for unit in runtime_lifecycle._V2_MANAGER_UNITS
    }

    def systemctl(arguments: tuple[str, ...]) -> dict[str, str]:
        if arguments[0] == "show":
            return states[arguments[1]]
        return {}

    journal = runtime_lifecycle.D320CutoverJournalV2.from_payload(payload)
    with runtime_lifecycle._lifecycle_lock(home) as lease:
        runtime_lifecycle._v2_store_journal(
            home, journal, expected_digest=None, lease=lease
        )
    monkeypatch.setattr(runtime_lifecycle, "_systemctl_default", systemctl)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            str(SCRIPT),
            "cutover",
            "--home",
            str(home),
            "--plan-sha256",
            journal.payload["plan_sha256"],
            "--phase",
            "recover",
        ],
    )
    assert runtime_lifecycle.main() == 0
    result = json.loads(capsys.readouterr().out)

    assert result["status"] == "runtime_lifecycle_recovery_complete", result
    final = runtime_lifecycle._v2_load_journal(home)
    assert final.payload["phase"] == "ROLLED_BACK"
    assert final.payload["recovery_count"] == 1
    assert not (home / ".local" / "lib").exists()
    assert not (home / ".config" / "systemd" / "user").exists()


def test_runtime_lifecycle_v2_rejects_boolean_only_consumer_pin(
    tmp_path: Path,
) -> None:
    payload = _runtime_v2_payload(tmp_path / "consumer-pin")
    payload["predecessor"] = {
        "generation": "e" * 40,
        "manifest_digest": "sha256:" + "f" * 64,
        "consumer_pin": True,
    }

    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.D320CutoverJournalV2.from_payload(payload)


def test_runtime_lifecycle_v2_successor_is_monotone_and_post_is_single_assignment(
    tmp_path: Path,
) -> None:
    initial = runtime_lifecycle.D320CutoverJournalV2.from_payload(
        _runtime_v2_payload(tmp_path / "successor")
    )
    next_payload = initial.payload
    next_payload["sequence"] = 2
    next_payload["phase"] = "SEALED"
    next_payload["sealed"] = {
        "generation": "a" * 40,
        "manifest_digest": "sha256:" + "1" * 64,
        "stage_identity_sha256": "2" * 64,
        "generation_identity_sha256": "3" * 64,
        "output_sha256": {
            key: "c" * 64
            for key in (
                "mcp_launcher",
                "hourly_service",
                "hourly_timer",
                "pricing_launcher",
                "pricing_service",
                "pricing_timer",
                "legacy_launcher",
            )
        },
    }
    stage_path = next(
        effect["path"]
        for effect in next_payload["extra_effects"]
        if effect["kind"] == "stage"
    )
    next_payload["steps"].append(
        {
            "sequence": 2,
            "phase": "SEALED",
            "action": "stage_sealed",
            "effect": stage_path,
            "sha256": "1" * 64,
        }
    )
    sealed = runtime_lifecycle.D320CutoverJournalV2.from_payload(next_payload)
    successor_validator = getattr(
        runtime_lifecycle, "validate_d320_v2_journal_successor", None
    )
    assert callable(successor_validator)
    assert successor_validator(initial, sealed) is None

    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        successor_validator(sealed, initial)


def _runtime_v2_observed_payload(home: Path) -> dict[str, object]:
    payload = _runtime_v2_payload(home)
    sequence = 1

    def append_step(
        phase: str, action: str, effect: str, digest: str = "2" * 64
    ) -> None:
        nonlocal sequence
        sequence += 1
        payload["steps"].append(
            {
                "sequence": sequence,
                "phase": phase,
                "action": action,
                "effect": effect,
                "sha256": digest,
            }
        )
        payload["phase"] = phase
        payload["sequence"] = sequence

    payload["sealed"] = {
        "generation": "a" * 40,
        "manifest_digest": "sha256:" + "1" * 64,
        "stage_identity_sha256": "2" * 64,
        "generation_identity_sha256": "3" * 64,
        "output_sha256": {
            key: "c" * 64
            for key in (
                "mcp_launcher",
                "hourly_service",
                "hourly_timer",
                "pricing_launcher",
                "pricing_service",
                "pricing_timer",
                "legacy_launcher",
            )
        },
    }
    stage_path = next(
        effect["path"]
        for effect in payload["extra_effects"]
        if effect["kind"] == "stage"
    )
    generation_path = next(
        effect["path"]
        for effect in payload["extra_effects"]
        if effect["kind"] == "generation"
    )
    append_step("SEALED", "stage_sealed", stage_path, "1" * 64)
    append_step("INSTALLED", "generation_published", generation_path, "1" * 64)
    append_step(
        "ACTIVATED",
        "manager_mutation",
        "manager:" + runtime_lifecycle._NEW_TIMER,
    )
    payload["post"] = {
        "files": copy.deepcopy(payload["files"]),
        "extra_effects": copy.deepcopy(payload["extra_effects"]),
        "manager_states": copy.deepcopy(payload["manager_pre"]),
    }
    for item in payload["files"]:
        append_step(
            "OBSERVED",
            "effect_readback",
            item["path"],
            hashlib.sha256(runtime_lifecycle._d320_canonical_json(item)).hexdigest(),
        )
    for item in payload["extra_effects"]:
        append_step(
            "OBSERVED",
            "effect_readback",
            item["path"],
            hashlib.sha256(runtime_lifecycle._d320_canonical_json(item)).hexdigest(),
        )
    for unit in runtime_lifecycle._V2_MANAGER_UNITS:
        state = payload["manager_pre"][unit]
        append_step(
            "OBSERVED",
            "manager_readback",
            "manager:" + unit,
            hashlib.sha256(runtime_lifecycle._d320_canonical_json(state)).hexdigest(),
        )
    return payload


def test_runtime_lifecycle_v2_rejects_observed_post_drift(
    tmp_path: Path,
) -> None:
    observed = runtime_lifecycle.D320CutoverJournalV2.from_payload(
        _runtime_v2_observed_payload(tmp_path / "observed")
    )
    changed = observed.payload
    changed["sequence"] += 1
    changed["phase"] = "COMMITTED"
    changed["steps"].append(
        {
            "sequence": changed["sequence"],
            "phase": "COMMITTED",
            "action": "commit_verified",
            "effect": next(
                effect["path"]
                for effect in changed["extra_effects"]
                if effect["kind"] == "journal"
            ),
            "sha256": "3" * 64,
        }
    )
    changed["post"]["manager_states"][runtime_lifecycle._NEW_TIMER]["ActiveState"] = (
        "failed"
    )
    with pytest.raises(
        runtime_lifecycle.D320CutoverJournalError,
        match="^d320_v2_post_readback_incomplete$",
    ):
        runtime_lifecycle.D320CutoverJournalV2.from_payload(changed)

    payload = _d332_payload(state="ROOT_ABI_VERIFIED", sequence=2)
    payload["history"][1]["at_unix_ms"] = 103
    with pytest.raises(runtime_lifecycle.D320CutoverJournalError):
        runtime_lifecycle.D320CutoverJournalV1.from_payload(payload)


def test_runtime_lifecycle_v2_owner_evidence_uses_only_fixed_receipt_paths(
    tmp_path: Path,
) -> None:
    payload = _runtime_v2_observed_payload(tmp_path / "owner-evidence")
    payload["sequence"] += 1
    payload["steps"].append(
        {
            "sequence": payload["sequence"],
            "phase": "OBSERVED",
            "action": "owner_evidence_readback",
            "effect": str(tmp_path / "foreign-receipt.json"),
            "sha256": "4" * 64,
        }
    )

    with pytest.raises(
        runtime_lifecycle.D320CutoverJournalError,
        match="d320_v2_step_binding_invalid",
    ):
        runtime_lifecycle.D320CutoverJournalV2.from_payload(payload)


def _root_hook_effect_fixture(root: Path, *, issued_at_unix_ns: int) -> tuple[str, str]:
    lock = root / ".root-hook-abi-owner.lock"
    lock.write_bytes(b"\n")
    lock.chmod(0o644)
    target = root / "v1"
    (target / "allowlists").mkdir(parents=True, mode=0o755)
    files = {
        "launcher": (b"#!/bin/sh\n", 0o755),
        "hook_session_pin_store.py": (b"PIN_STORE = 1\n", 0o644),
        "hook_abi_v1_core.py": (b"CORE = 1\n", 0o644),
    }
    allowlist = b'{"allow":true}\n'
    files["allowlists/" + hashlib.sha256(allowlist).hexdigest() + ".json"] = (
        allowlist,
        0o644,
    )
    payload = {}
    for name, (content, mode) in files.items():
        path = target / name
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
        path.write_bytes(content)
        path.chmod(mode)
        payload[name] = {
            "mode": mode,
            "nlink": 1,
            "sha256": hashlib.sha256(content).hexdigest(),
            "size": len(content),
        }
    generation = "a" * 40
    manifest_digest = "sha256:" + "b" * 64
    receipt = {
        "effect": "root_hook_abi_verified_present",
        "files": payload,
        "generation": generation,
        "issued_at_unix_ns": issued_at_unix_ns,
        "manifest_digest": manifest_digest,
        "owner": "root_hook_abi_v1",
        "root_uid": os.geteuid(),
        "schema_version": 1,
        "source_uid": os.geteuid(),
        "target": str(target),
    }
    (root / "root-hook-effect-receipt-v1.json").write_text(
        json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n"
    )
    return generation, manifest_digest


def test_root_hook_receipt_consumer_binds_fresh_physical_effect(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    parent = tmp_path / "root-owner"
    parent.mkdir(mode=0o755)
    parent.chmod(0o755)
    generation, manifest_digest = _root_hook_effect_fixture(
        parent, issued_at_unix_ns=time.time_ns()
    )
    monkeypatch.setattr(runtime_lifecycle, "_ROOT_HOOK_ABI_PARENT", parent)
    monkeypatch.setattr(runtime_lifecycle, "_ROOT_HOOK_ABI_UID", os.geteuid())
    monkeypatch.setattr(runtime_lifecycle, "_ROOT_HOOK_ABI_GID", os.getegid())

    receipt_digest = runtime_lifecycle._verify_root_hook_effect_receipt(
        generation=generation, manifest_digest=manifest_digest
    )

    assert len(receipt_digest) == 64
    with pytest.raises(
        runtime_lifecycle.RuntimeLifecycleError,
        match="runtime_lifecycle_root_hook_effect_unverified",
    ):
        runtime_lifecycle._verify_root_hook_effect_receipt(
            generation="c" * 40, manifest_digest=manifest_digest
        )
    unexpected = parent / "v1/unexpected"
    unexpected.write_bytes(b"extra root member\n")
    unexpected.chmod(0o644)
    with pytest.raises(
        runtime_lifecycle.RuntimeLifecycleError,
        match="runtime_lifecycle_root_hook_effect_unverified",
    ):
        runtime_lifecycle._verify_root_hook_effect_receipt(
            generation=generation, manifest_digest=manifest_digest
        )
    unexpected.unlink()
    (parent / "v1/hook_abi_v1_core.py").write_bytes(b"CORE = changed\n")
    with pytest.raises(
        runtime_lifecycle.RuntimeLifecycleError,
        match="runtime_lifecycle_root_hook_effect_unverified",
    ):
        runtime_lifecycle._verify_root_hook_effect_receipt(
            generation=generation, manifest_digest=manifest_digest
        )


def test_root_hook_receipt_consumer_holds_expired_or_wrong_generation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    parent = tmp_path / "root-owner"
    parent.mkdir(mode=0o755)
    parent.chmod(0o755)
    generation, manifest_digest = _root_hook_effect_fixture(parent, issued_at_unix_ns=1)
    monkeypatch.setattr(runtime_lifecycle, "_ROOT_HOOK_ABI_PARENT", parent)
    monkeypatch.setattr(runtime_lifecycle, "_ROOT_HOOK_ABI_UID", os.geteuid())
    monkeypatch.setattr(runtime_lifecycle, "_ROOT_HOOK_ABI_GID", os.getegid())

    with pytest.raises(
        runtime_lifecycle.RuntimeLifecycleError,
        match="runtime_lifecycle_owner_receipt_expired",
    ):
        runtime_lifecycle._verify_root_hook_effect_receipt(
            generation=generation, manifest_digest=manifest_digest
        )


def _plugin_release_effect_fixture(
    home: Path, *, issued_at_unix_ns: int
) -> tuple[str, str]:
    generation = "a" * 40
    manifest_digest = "sha256:" + "b" * 64
    state_root = home / ".local/state/codex-master-mcp/hive"
    plugin = home / "plugins/the-hive"
    marketplace_path = home / ".agents/plugins/marketplace.json"
    for directory in (state_root, plugin, marketplace_path.parent):
        directory.mkdir(parents=True, mode=0o700)
        directory.chmod(0o700)
    descriptor = b'{"release":"fixture"}\n'
    marketplace = b'{"name":"personal","plugins":[]}\n'
    target = plugin / "release-binding.json"
    target.write_bytes(descriptor)
    target.chmod(0o644)
    marketplace_path.write_bytes(marketplace)
    marketplace_path.chmod(0o644)
    target_info = target.stat()
    plugin_info = plugin.stat()
    receipt = {
        "descriptor_sha256": "sha256:" + hashlib.sha256(descriptor).hexdigest(),
        "effect": "plugin_release_descriptor_verified_present",
        "generation": generation,
        "issued_at_unix_ns": issued_at_unix_ns,
        "manifest_digest": manifest_digest,
        "marketplace_sha256": hashlib.sha256(marketplace).hexdigest(),
        "owner": "plugin_release_publisher",
        "plugin_identity": {"dev": plugin_info.st_dev, "ino": plugin_info.st_ino},
        "schema_version": 1,
        "target": "plugins/the-hive/release-binding.json",
        "target_identity": {
            "dev": target_info.st_dev,
            "gid": target_info.st_gid,
            "ino": target_info.st_ino,
            "mode": stat.S_IMODE(target_info.st_mode),
            "nlink": target_info.st_nlink,
            "size": target_info.st_size,
            "uid": target_info.st_uid,
        },
    }
    receipt_path = state_root / "plugin-release-effect-receipt-v1.json"
    receipt_path.write_text(
        json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n"
    )
    receipt_path.chmod(0o600)
    return generation, manifest_digest


def test_plugin_release_receipt_consumer_binds_fresh_physical_effect(
    tmp_path: Path,
) -> None:
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    generation, manifest_digest = _plugin_release_effect_fixture(
        home, issued_at_unix_ns=time.time_ns()
    )

    receipt_digest = runtime_lifecycle._verify_plugin_release_effect_receipt(
        home=home, generation=generation, manifest_digest=manifest_digest
    )

    assert len(receipt_digest) == 64
    with pytest.raises(
        runtime_lifecycle.RuntimeLifecycleError,
        match="runtime_lifecycle_plugin_effect_unverified",
    ):
        runtime_lifecycle._verify_plugin_release_effect_receipt(
            home=home,
            generation="c" * 40,
            manifest_digest=manifest_digest,
        )
    (home / "plugins/the-hive/release-binding.json").write_bytes(b"changed\n")
    with pytest.raises(
        runtime_lifecycle.RuntimeLifecycleError,
        match="runtime_lifecycle_plugin_effect_unverified",
    ):
        runtime_lifecycle._verify_plugin_release_effect_receipt(
            home=home, generation=generation, manifest_digest=manifest_digest
        )


def test_plugin_release_receipt_consumer_holds_expired_or_wrong_generation(
    tmp_path: Path,
) -> None:
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    generation, manifest_digest = _plugin_release_effect_fixture(
        home, issued_at_unix_ns=1
    )

    with pytest.raises(
        runtime_lifecycle.RuntimeLifecycleError,
        match="runtime_lifecycle_owner_receipt_expired",
    ):
        runtime_lifecycle._verify_plugin_release_effect_receipt(
            home=home, generation=generation, manifest_digest=manifest_digest
        )
