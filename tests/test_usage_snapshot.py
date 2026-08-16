from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from functools import partial
from pathlib import Path
from typing import Callable

import pytest

from codex_master.usage_snapshot import (
    AccountUsage,
    LauncherSpec,
    ProcessResult,
    UsageSnapshot,
    UsageSnapshotUnavailable,
    load_account_usage_v1,
    read_active_launcher_v1,
)
import codex_master.usage_snapshot as usage_snapshot


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "account_usage_v1"
NOW = datetime(2026, 8, 15, 12, 0, tzinfo=timezone.utc)
MAX_STDOUT = 2 * 1024 * 1024
MAX_STDERR = 4096


def fixture(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


def write_private(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    path.parent.chmod(0o700)
    path.write_bytes(data)
    path.chmod(0o600)


def make_active_tree(tmp_path: Path) -> tuple[Path, Path, Path, Path]:
    state_home = tmp_path / "state-home"
    integration = state_home / "codex-usage" / "integration"
    releases = integration / "releases"
    release = releases / "release-1"
    launcher = release / "venv" / "bin" / "codex-usage"
    launcher.parent.mkdir(parents=True, mode=0o700)
    for directory in (
        state_home,
        state_home / "codex-usage",
        integration,
        releases,
        release,
        release / "venv",
        launcher.parent,
    ):
        directory.chmod(0o700)
    launcher.write_bytes(b"#!/bin/sh\n")
    launcher.chmod(0o700)
    active = integration / "active.json"
    write_private(
        active,
        json.dumps(
            {
                "release_dir": str(release),
                "launcher_path": str(launcher),
                "schema_version": 1,
            },
            separators=(",", ":"),
        ).encode(),
    )
    return state_home, active, release, launcher


def make_cache_tree(tmp_path: Path, payload: bytes) -> tuple[Path, Path]:
    state_home = tmp_path / "state-home"
    integration = state_home / "codex-usage" / "integration"
    integration.mkdir(parents=True, mode=0o700)
    for directory in (state_home, state_home / "codex-usage", integration):
        directory.chmod(0o700)
    cache = integration / "account-usage-v1.json"
    write_private(cache, payload)
    return state_home, cache


def active_reader(state_home: Path) -> Callable[[], LauncherSpec]:
    return lambda: read_active_launcher_v1(state_home=state_home)


class Runner:
    def __init__(self, result: ProcessResult | Exception) -> None:
        self.result = result
        self.calls: list[tuple[tuple[str, ...], float, int, int]] = []

    def __call__(
        self, argv: tuple[str, ...], timeout: float, stdout_limit: int, stderr_limit: int
    ) -> ProcessResult:
        self.calls.append((argv, timeout, stdout_limit, stderr_limit))
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


class Cache:
    def __init__(self, payload: bytes | Exception) -> None:
        self.payload = payload
        self.calls: list[int] = []

    def __call__(self, maximum: int) -> bytes:
        self.calls.append(maximum)
        if isinstance(self.payload, Exception):
            raise self.payload
        return self.payload


def load_with(
    *,
    active: Callable[[], LauncherSpec],
    runner: Runner,
    cache: Cache,
    known: frozenset[str] = frozenset({"alpha", "beta", "zeta"}),
    clock: Callable[[], datetime] = lambda: NOW,
) -> UsageSnapshot:
    return load_account_usage_v1(
        active_release_reader=active,
        runner=runner,
        cache_reader=cache,
        known_account_ids=known,
        clock=clock,
    )


def unavailable(snapshot: UsageSnapshot) -> None:
    assert snapshot == UsageSnapshot((), "unavailable", True, ("usage_unavailable",))
    assert "SYNTHETIC_SECRET_MARKER" not in repr(snapshot)
    assert "launcher" not in repr(snapshot).casefold()


def test_live_snapshot_uses_exact_absolute_launcher_argv_and_exact_account_ids(tmp_path: Path) -> None:
    state_home, _, _, launcher = make_active_tree(tmp_path)
    runner = Runner(ProcessResult(0, fixture("valid.json"), b""))
    cache = Cache(FileNotFoundError())
    snapshot = load_with(
        active=active_reader(state_home), runner=runner, cache=cache, known=frozenset({"alpha", "missing"})
    )

    assert snapshot.source == "live"
    assert snapshot.stale is False
    assert [account.account_id for account in snapshot.accounts] == ["alpha"]
    assert isinstance(snapshot.accounts[0], AccountUsage)
    assert snapshot.accounts[0].status == "ok"
    assert runner.calls == [
        ((str(launcher), "integration-snapshot", "--schema", "1", "--format", "json"), 5.0, MAX_STDOUT, MAX_STDERR)
    ]
    assert cache.calls == []


@pytest.mark.parametrize(
    "manifest_change",
    [
        lambda manifest, _state, _active, _release, _launcher: manifest.update({"schema_version": True}),
        lambda manifest, _state, _active, _release, _launcher: manifest.update({"schema_version": 2}),
        lambda manifest, _state, _active, _release, _launcher: manifest.update({"release_dir": "relative"}),
        lambda manifest, _state, _active, _release, _launcher: manifest.update({"release_dir": "/tmp/a\x00b"}),
        lambda manifest, state, _active, _release, _launcher: manifest.update(
            {"release_dir": str(state / "foreign"), "launcher_path": str(state / "foreign" / "venv" / "bin" / "codex-usage")}
        ),
        lambda manifest, state, _active, _release, _launcher: manifest.update(
            {"release_dir": str(state / "codex-usage" / "integration" / "releases" / "nested" / "release")}
        ),
        lambda manifest, _state, _active, release, _launcher: manifest.update(
            {"launcher_path": str(release / "venv" / "bin" / "other")}
        ),
    ],
    ids=["bool-version", "wrong-version", "relative-release", "nul-release", "foreign-release", "nested-release", "wrong-launcher"],
)
def test_active_launcher_v1_rejects_invalid_locator_without_runner(
    tmp_path: Path, manifest_change: Callable[..., None]
) -> None:
    state_home, active, release, launcher = make_active_tree(tmp_path)
    manifest = json.loads(active.read_bytes())
    manifest_change(manifest, state_home, active, release, launcher)
    write_private(active, json.dumps(manifest).encode())
    runner = Runner(ProcessResult(0, fixture("valid.json"), b""))
    cache = Cache(FileNotFoundError())

    snapshot = load_with(active=active_reader(state_home), runner=runner, cache=cache)

    unavailable(snapshot)
    assert runner.calls == []


@pytest.mark.parametrize("mutation", ["symlink", "hardlink", "mode", "size", "uid"])
def test_active_launcher_v1_rejects_unsafe_launcher_without_runner(tmp_path: Path, mutation: str) -> None:
    state_home, active, release, launcher = make_active_tree(tmp_path)
    if mutation == "symlink":
        target = tmp_path / "outside-launcher"
        target.write_bytes(b"outside")
        launcher.unlink()
        launcher.symlink_to(target)
    elif mutation == "hardlink":
        target = tmp_path / "linked-launcher"
        target.write_bytes(b"outside")
        target.chmod(0o700)
        launcher.unlink()
        os.link(target, launcher)
    elif mutation == "mode":
        launcher.chmod(0o644)
    elif mutation == "size":
        active.write_bytes(b"{" + b"x" * (128 * 1024) + b"}")
        active.chmod(0o600)
    else:
        real_getuid = os.getuid
        monkeypatch = pytest.MonkeyPatch()
        monkeypatch.setattr(usage_snapshot.os, "getuid", lambda: real_getuid() + 1)
    runner = Runner(ProcessResult(0, fixture("valid.json"), b""))
    cache = Cache(FileNotFoundError())

    try:
        snapshot = load_with(active=active_reader(state_home), runner=runner, cache=cache)
    finally:
        if mutation == "uid":
            monkeypatch.undo()

    unavailable(snapshot)
    assert runner.calls == []


@pytest.mark.parametrize("swap_kind", ["file", "parent"])
def test_active_launcher_v1_rejects_parent_or_file_inode_swap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, swap_kind: str
) -> None:
    state_home, active, _, _ = make_active_tree(tmp_path)
    original = usage_snapshot._read_bounded_bytes

    def swap_after_read(
        path: Path, maximum: int, expected: tuple[int, int, int]
    ) -> bytes:
        payload = original(path, maximum, expected)
        if swap_kind == "file":
            replacement = path.with_name("replacement.json")
            write_private(replacement, payload)
            os.replace(replacement, path)
        else:
            parent = path.parent
            old_parent = parent.with_name("integration-old")
            parent.rename(old_parent)
            parent.mkdir(mode=0o700)
            parent.chmod(0o700)
        return payload

    monkeypatch.setattr(usage_snapshot, "_read_bounded_bytes", swap_after_read)
    with pytest.raises(UsageSnapshotUnavailable):
        read_active_launcher_v1(state_home=state_home)
    assert active.exists() is (swap_kind == "file")


def test_active_json_open_binds_preopen_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state_home, active, _, _ = make_active_tree(tmp_path)
    real_open = usage_snapshot.os.open
    saved = active.with_name("active-original.json")

    def swap_before_open(path: Path, flags: int) -> int:
        if Path(path) != active:
            return real_open(path, flags)
        active.rename(saved)
        write_private(active, b"{}")
        try:
            return real_open(path, flags)
        finally:
            active.unlink()
            saved.rename(active)

    monkeypatch.setattr(usage_snapshot.os, "open", swap_before_open)
    with pytest.raises(UsageSnapshotUnavailable):
        read_active_launcher_v1(state_home=state_home)


def test_active_target_layout_swap_after_launcher_check_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state_home, _, _, launcher = make_active_tree(tmp_path)
    original = usage_snapshot._launcher_identity

    def swap_after_check(path: Path) -> tuple[int, int, int]:
        identity = original(path)
        replacement = path.with_name("replacement-launcher")
        replacement.write_bytes(b"replacement")
        replacement.chmod(0o700)
        os.replace(replacement, path)
        return identity

    monkeypatch.setattr(usage_snapshot, "_launcher_identity", swap_after_check)
    with pytest.raises(UsageSnapshotUnavailable):
        read_active_launcher_v1(state_home=state_home)
    assert launcher.read_bytes() == b"replacement"


def test_active_pointer_never_uses_path_or_attestation_import(tmp_path: Path) -> None:
    state_home, active, _, _ = make_active_tree(tmp_path)
    manifest = json.loads(active.read_bytes())
    manifest["launcher_path"] = "relative-launcher"
    write_private(active, json.dumps(manifest).encode())
    assert not any(name == "codex_usage" or name.startswith("codex_usage.") for name in os.sys.modules)
    runner = Runner(ProcessResult(0, fixture("valid.json"), b""))
    cache = Cache(FileNotFoundError())

    snapshot = load_with(active=active_reader(state_home), runner=runner, cache=cache)

    unavailable(snapshot)
    assert runner.calls == []


@pytest.mark.parametrize("stream", ["stdout", "stderr"])
def test_default_runner_streams_limits_and_reaps_without_communicate(
    monkeypatch: pytest.MonkeyPatch, stream: str
) -> None:
    stdout_read, stdout_write = os.pipe()
    stderr_read, stderr_write = os.pipe()
    os.write(stdout_write, b"012345" if stream == "stdout" else b"okay")
    os.write(stderr_write, b"012345" if stream == "stderr" else b"")
    os.close(stdout_write)
    os.close(stderr_write)

    class FakeProcess:
        pid = 813
        returncode = 0

        def __init__(self) -> None:
            self.stdout = os.fdopen(stdout_read, "rb", buffering=0)
            self.stderr = os.fdopen(stderr_read, "rb", buffering=0)
            self.communicate_calls = 0
            self.waited = False

        def communicate(self, **_kwargs: object) -> tuple[bytes, bytes]:
            self.communicate_calls += 1
            raise AssertionError("unbounded communicate")

        def wait(self, **_kwargs: object) -> int:
            self.waited = True
            return self.returncode

        def kill(self) -> None:
            self.waited = True

    process = FakeProcess()
    killed: list[tuple[int, int]] = []
    monkeypatch.setattr(usage_snapshot.subprocess, "Popen", lambda *_args, **_kwargs: process)
    monkeypatch.setattr(usage_snapshot.os, "killpg", lambda pid, sig: killed.append((pid, sig)))

    try:
        with pytest.raises(usage_snapshot._Invalid):
            usage_snapshot._default_runner(("/synthetic/launcher",), 5.0, 4, 4)
    finally:
        process.stdout.close()
        process.stderr.close()

    assert process.communicate_calls == 0
    assert process.waited is True
    assert killed == [(813, usage_snapshot.signal.SIGKILL)]


def test_bounded_runner_is_exported_without_a_second_implementation() -> None:
    assert usage_snapshot.default_runner is usage_snapshot._default_runner


def test_usage_clock_is_sampled_once_after_live_runner() -> None:
    events: list[str] = []

    def runner(
        _argv: tuple[str, ...], _timeout: float, _stdout_limit: int, _stderr_limit: int
    ) -> ProcessResult:
        events.append("runner")
        return ProcessResult(0, fixture("valid.json"), b"")

    def clock() -> datetime:
        events.append("usage-clock")
        return NOW

    def cache_reader(_maximum: int) -> bytes:
        events.append("cache")
        raise AssertionError("fresh live snapshot must not read cache")

    snapshot = load_account_usage_v1(
        active_release_reader=lambda: LauncherSpec(Path("/synthetic/launcher")),
        runner=runner,
        cache_reader=cache_reader,
        known_account_ids=frozenset({"alpha"}),
        clock=clock,
    )

    assert snapshot.source == "live"
    assert events == ["runner", "usage-clock"]


def test_live_runner_failure_reads_cache_before_sampling_usage_clock() -> None:
    events: list[str] = []

    def runner(
        _argv: tuple[str, ...], _timeout: float, _stdout_limit: int, _stderr_limit: int
    ) -> ProcessResult:
        events.append("runner")
        raise RuntimeError("synthetic-live-failure")

    def cache_reader(_maximum: int) -> bytes:
        events.append("cache")
        return fixture("stale.json")

    def clock() -> datetime:
        events.append("usage-clock")
        return NOW

    snapshot = load_account_usage_v1(
        active_release_reader=lambda: LauncherSpec(Path("/synthetic/launcher")),
        runner=runner,
        cache_reader=cache_reader,
        known_account_ids=frozenset({"alpha"}),
        clock=clock,
    )

    assert snapshot.source == "cache"
    assert events == ["runner", "cache", "usage-clock"]


@pytest.mark.parametrize(
    ("live_generated_at", "cache_generated_at", "expected_source"),
    [
        ("2026-08-15T11:44:59Z", "2026-08-15T11:30:00Z", "cache"),
        ("2026-08-15T12:00:01Z", "2026-08-15T11:30:00Z", "cache"),
        ("2026-08-15T11:44:59Z", "2026-08-15T10:59:00Z", "unavailable"),
        ("2026-08-15T12:00:01Z", "2026-08-15T12:00:01Z", "unavailable"),
    ],
    ids=["stale-live-valid-cache", "future-live-valid-cache", "stale-live-old-cache", "future-live-future-cache"],
)
def test_parseable_stale_or_future_live_samples_clock_before_cache(
    live_generated_at: str, cache_generated_at: str, expected_source: str
) -> None:
    events: list[str] = []
    live_document = json.loads(fixture("valid.json"))
    live_document["generated_at"] = live_generated_at
    cache_document = json.loads(fixture("stale.json"))
    cache_document["generated_at"] = cache_generated_at

    def runner(
        _argv: tuple[str, ...], _timeout: float, _stdout_limit: int, _stderr_limit: int
    ) -> ProcessResult:
        events.append("runner")
        return ProcessResult(0, json.dumps(live_document).encode(), b"")

    def clock() -> datetime:
        events.append("usage-clock")
        return NOW

    def cache_reader(_maximum: int) -> bytes:
        events.append("cache")
        return json.dumps(cache_document).encode()

    snapshot = load_account_usage_v1(
        active_release_reader=lambda: LauncherSpec(Path("/synthetic/launcher")),
        runner=runner,
        cache_reader=cache_reader,
        known_account_ids=frozenset({"alpha"}),
        clock=clock,
    )

    assert events == ["runner", "usage-clock", "cache"]
    assert events.count("usage-clock") == 1
    assert snapshot.source == expected_source


def test_cache_reader_success_and_partial_composes_with_cache_reader_api(tmp_path: Path) -> None:
    payload = fixture("stale.json")
    state_home, _ = make_cache_tree(tmp_path, payload)

    assert usage_snapshot.read_account_usage_cache_v1(MAX_STDOUT, state_home=state_home) == payload
    positional_snapshot = load_account_usage_v1(
        active_release_reader=lambda: (_ for _ in ()).throw(RuntimeError("no-live")),
        runner=Runner(RuntimeError("no-process")),
        cache_reader=lambda limit: payload,
        known_account_ids=frozenset({"alpha"}),
        clock=lambda: NOW,
    )
    assert positional_snapshot.source == "cache"
    snapshot = load_account_usage_v1(
        active_release_reader=lambda: (_ for _ in ()).throw(RuntimeError("no-live")),
        runner=Runner(RuntimeError("no-process")),
        cache_reader=partial(usage_snapshot.read_account_usage_cache_v1, state_home=state_home),
        known_account_ids=frozenset({"alpha"}),
        clock=lambda: NOW,
    )
    assert snapshot.source == "cache"
    assert snapshot.stale is True


@pytest.mark.parametrize("mutation", ["symlink", "mode", "hardlink", "uid", "oversize"])
def test_cache_reader_rejects_unsafe_nofollow_inputs_without_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutation: str
) -> None:
    payload = fixture("stale.json")
    state_home, cache = make_cache_tree(tmp_path, payload)
    outside = tmp_path / "outside-cache"
    outside.write_bytes(payload)
    outside.chmod(0o600)
    if mutation == "symlink":
        cache.unlink()
        cache.symlink_to(outside)
    elif mutation == "mode":
        cache.chmod(0o644)
    elif mutation == "hardlink":
        cache.unlink()
        os.link(outside, cache)
    elif mutation == "uid":
        real_getuid = os.getuid
        monkeypatch.setattr(usage_snapshot.os, "getuid", lambda: real_getuid() + 1)
    else:
        cache.write_bytes(b"x" * (MAX_STDOUT + 1))
        cache.chmod(0o600)
    before = outside.read_bytes()

    with pytest.raises(UsageSnapshotUnavailable):
        usage_snapshot.read_account_usage_cache_v1(state_home=state_home, maximum=MAX_STDOUT)

    assert outside.read_bytes() == before
    assert state_home.stat().st_mode & 0o777 == 0o700
    assert (state_home / "codex-usage").stat().st_mode & 0o777 == 0o700


@pytest.mark.parametrize("swap_kind", ["file", "parent"])
def test_cache_reader_rejects_file_or_parent_inode_swap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, swap_kind: str
) -> None:
    payload = fixture("stale.json")
    state_home, cache = make_cache_tree(tmp_path, payload)
    original = usage_snapshot._read_bounded_bytes
    if swap_kind == "file":
        real_open = usage_snapshot.os.open
        saved = cache.with_name("cache-original.json")

        def swap_before_open(path: Path, flags: int) -> int:
            if Path(path) != cache:
                return real_open(path, flags)
            cache.rename(saved)
            write_private(cache, b"{}")
            descriptor = real_open(path, flags)
            cache.unlink()
            saved.rename(cache)
            return descriptor

        monkeypatch.setattr(usage_snapshot.os, "open", swap_before_open)
    else:
        def swap_after_read(path: Path, maximum: int, expected: tuple[int, int, int]) -> bytes:
            result = original(path, maximum, expected)
            parent = path.parent
            old_parent = parent.with_name("integration-old")
            parent.rename(old_parent)
            parent.mkdir(mode=0o700)
            parent.chmod(0o700)
            return result

        monkeypatch.setattr(usage_snapshot, "_read_bounded_bytes", swap_after_read)

    with pytest.raises(UsageSnapshotUnavailable):
        usage_snapshot.read_account_usage_cache_v1(state_home=state_home, maximum=MAX_STDOUT)


@pytest.mark.parametrize(
    "result",
    [
        ProcessResult(69, fixture("valid.json"), b""),
        ProcessResult(0, fixture("valid.json"), b"stderr-marker"),
        ProcessResult(0, b"x" * (MAX_STDOUT + 1), b""),
        ProcessResult(0, fixture("valid.json"), b"x" * (MAX_STDERR + 1)),
    ],
    ids=["nonzero", "stderr", "stdout-oversize", "stderr-oversize"],
)
def test_runner_contract_uses_fixed_argv_and_rejects_stderr_or_limits(
    result: ProcessResult, tmp_path: Path
) -> None:
    runner = Runner(result)
    cache = Cache(fixture("stale.json"))
    spec = LauncherSpec(Path("/synthetic/launcher"))

    snapshot = load_with(active=lambda: spec, runner=runner, cache=cache)

    assert runner.calls == [(('/synthetic/launcher', "integration-snapshot", "--schema", "1", "--format", "json"), 5.0, MAX_STDOUT, MAX_STDERR)]
    assert snapshot.source == "cache"
    assert snapshot.stale is True


@pytest.mark.parametrize("error", [TimeoutError("timeout-marker"), OSError("spawn-marker")])
def test_runner_errors_use_cache_without_detail(tmp_path: Path, error: Exception) -> None:
    runner = Runner(error)
    cache = Cache(fixture("stale.json"))
    snapshot = load_with(
        active=lambda: LauncherSpec(Path("/synthetic/launcher")), runner=runner, cache=cache
    )
    assert snapshot.source == "cache"
    assert snapshot.stale is True
    assert "marker" not in repr(snapshot).casefold()


def test_active_swap_exit_69_uses_cache_without_consumer_lock() -> None:
    runner = Runner(ProcessResult(69, fixture("valid.json"), b""))
    cache = Cache(fixture("stale.json"))

    snapshot = load_with(
        active=lambda: LauncherSpec(Path("/synthetic/launcher")), runner=runner, cache=cache
    )

    assert snapshot.source == "cache"
    assert snapshot.stale is True
    assert [account.account_id for account in snapshot.accounts] == ["alpha"]


@pytest.mark.parametrize(
    "bad_document",
    ["schema", "duplicate", "naive-time", "offset-time", "bounds", "null-resets"],
)
def test_schema_secret_freshness_and_exact_account_mapping(
    bad_document: str,
) -> None:
    document = json.loads(fixture("valid.json"))
    if bad_document == "schema":
        document["schema_version"] = True
    elif bad_document == "duplicate":
        document["accounts"].append(document["accounts"][0])
    elif bad_document == "naive-time":
        document["generated_at"] = "2026-08-15T12:00:00"
    elif bad_document == "offset-time":
        document["generated_at"] = "2026-08-15T13:00:00+01:00"
    elif bad_document == "bounds":
        document["accounts"][0]["limits"] = [
            {
                "pool": f"pool-{index}",
                "window_seconds": 18000,
                "used_percent": 1.0,
                "remaining_percent": 99.0,
            }
            for index in range(33)
        ]
    else:
        document["accounts"][0]["usage_resets"] = None
    runner = Runner(ProcessResult(0, json.dumps(document).encode(), b""))
    cache = Cache(FileNotFoundError())

    snapshot = load_with(
        active=lambda: LauncherSpec(Path("/synthetic/launcher")), runner=runner, cache=cache
    )

    unavailable(snapshot)


def test_schema_secret_gate_rejects_key_and_value_markers_without_leak() -> None:
    payload = json.loads(fixture("secret-marker.json"))
    runner = Runner(ProcessResult(0, json.dumps(payload).encode(), b""))
    cache = Cache(FileNotFoundError())

    snapshot = load_with(
        active=lambda: LauncherSpec(Path("/synthetic/launcher")), runner=runner, cache=cache
    )

    unavailable(snapshot)
    assert snapshot.warnings == ("usage_unavailable",)


@pytest.mark.parametrize("bad_key", ["BadField", "bad-field", "_bad"])
def test_schema_rejects_non_snake_case_unknown_keys(bad_key: str) -> None:
    document = json.loads(fixture("valid.json"))
    document[bad_key] = "harmless"
    snapshot = load_with(
        active=lambda: LauncherSpec(Path("/synthetic/launcher")),
        runner=Runner(ProcessResult(0, json.dumps(document).encode(), b"")),
        cache=Cache(FileNotFoundError()),
    )
    unavailable(snapshot)


def test_limit_sort_handles_none_and_utc_reset_deterministically() -> None:
    document = json.loads(fixture("valid.json"))
    document["accounts"][0]["limits"].append(
        {
            "pool": "primary",
            "remaining_percent": 90.0,
            "used_percent": 10.0,
            "window_seconds": 18000,
        }
    )
    snapshot = load_with(
        active=lambda: LauncherSpec(Path("/synthetic/launcher")),
        runner=Runner(ProcessResult(0, json.dumps(document).encode(), b"")),
        cache=Cache(FileNotFoundError()),
        known=frozenset({"alpha"}),
    )
    assert snapshot.source == "live"
    assert [limit.reset_at for limit in snapshot.accounts[0].limits] == [
        None,
        datetime(2026, 8, 15, 13, 0, tzinfo=timezone.utc),
    ]


def test_live_stale_accounts_are_filtered_and_cache_accounts_are_all_stale() -> None:
    live_document = json.loads(fixture("valid.json"))
    live_document["accounts"][0]["freshness"]["stale"] = True
    live_runner = Runner(ProcessResult(0, json.dumps(live_document).encode(), b""))
    live_snapshot = load_with(
        active=lambda: LauncherSpec(Path("/synthetic/launcher")),
        runner=live_runner,
        cache=Cache(FileNotFoundError()),
        known=frozenset({"alpha", "outsider"}),
    )
    assert [account.account_id for account in live_snapshot.accounts] == ["outsider"]

    cache_runner = Runner(RuntimeError("live-failure"))
    cache_snapshot = load_with(
        active=lambda: LauncherSpec(Path("/synthetic/launcher")),
        runner=cache_runner,
        cache=Cache(fixture("multi-account.json")),
        known=frozenset({"alpha", "zeta"}),
    )
    assert cache_snapshot.stale is True
    assert all(account.stale for account in cache_snapshot.accounts)


@pytest.mark.parametrize("case", ["cost-bound", "reset-bound", "reset-shape", "nonfinite", "duplicate-key"])
def test_schema_rejects_cost_reset_finite_and_duplicate_key_boundaries(case: str) -> None:
    document = json.loads(fixture("valid.json"))
    if case == "cost-bound":
        document["accounts"][0]["cost_windows"] = [
            {
                "lookback_seconds": 3600,
                "pool": f"pool-{index}",
                "limit_window_seconds": 18000,
                "consumed_percentage_points": 1.0,
                "coverage": "complete",
                "sample_count": 1,
            }
            for index in range(65)
        ]
        payload = json.dumps(document).encode()
    elif case == "reset-bound":
        document["accounts"][0]["usage_resets"]["available"] = 10001
        payload = json.dumps(document).encode()
    elif case == "reset-shape":
        del document["accounts"][0]["usage_resets"]["known"]
        payload = json.dumps(document).encode()
    elif case == "nonfinite":
        document["accounts"][0]["cost_windows"] = [
            {
                "lookback_seconds": 3600,
                "pool": "primary",
                "limit_window_seconds": 18000,
                "consumed_percentage_points": float("nan"),
                "coverage": "complete",
                "sample_count": 1,
            }
        ]
        payload = json.dumps(document).encode()
    else:
        payload = b'{"accounts":[],"generated_at":"2026-08-15T12:00:00Z","schema_version":1,"schema_version":1}'
    snapshot = load_with(
        active=lambda: LauncherSpec(Path("/synthetic/launcher")),
        runner=Runner(ProcessResult(0, payload, b"")),
        cache=Cache(FileNotFoundError()),
    )
    unavailable(snapshot)


def test_unknown_fields_are_ignored_and_result_is_sorted() -> None:
    runner = Runner(ProcessResult(0, fixture("unknown-fields.json"), b""))
    snapshot = load_with(
        active=lambda: LauncherSpec(Path("/synthetic/launcher")),
        runner=runner,
        cache=Cache(FileNotFoundError()),
        known=frozenset({"zeta", "alpha", "missing"}),
    )

    assert [account.account_id for account in snapshot.accounts] == ["alpha", "zeta"]
    assert [account.status for account in snapshot.accounts] == ["partial", "ok"]
    assert snapshot.warnings == ()


@pytest.mark.parametrize(
    "cache_time, expected_source",
    [
        (datetime(2026, 8, 15, 11, 0, tzinfo=timezone.utc), "cache"),
        (datetime(2026, 8, 15, 10, 59, tzinfo=timezone.utc), "unavailable"),
        (datetime(2026, 8, 15, 12, 1, tzinfo=timezone.utc), "unavailable"),
    ],
    ids=["sixty-minutes", "too-old", "future"],
)
def test_cache_fallback_is_always_stale_and_age_bounded(
    cache_time: datetime, expected_source: str
) -> None:
    document = json.loads(fixture("stale.json"))
    document["generated_at"] = cache_time.isoformat().replace("+00:00", "Z")
    clock_calls: list[int] = []

    def clock() -> datetime:
        clock_calls.append(1)
        return NOW

    snapshot = load_with(
        active=lambda: LauncherSpec(Path("/synthetic/launcher")),
        runner=Runner(RuntimeError("live-failure")),
        cache=Cache(json.dumps(document).encode()),
        clock=clock,
    )

    assert snapshot.source == expected_source
    assert snapshot.stale is True
    assert len(clock_calls) == 1
    if expected_source == "unavailable":
        unavailable(snapshot)
