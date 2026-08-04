import os
import fcntl
import stat
from unittest.mock import patch
from contextlib import contextmanager
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

import pytest

from codex_master.fleet_registry import (
    AuthKind,
    FleetAccount,
    FleetSeries,
    FleetSnapshot,
    LimitState,
    Provider,
    RunnerKind,
    SecretState,
)
from codex_master.fleet_runners import ProbeResult, ProviderError


def test_fleet_paths_keep_registry_and_secrets_separate(tmp_path: Path) -> None:
    from codex_master.fleet_service import FleetPaths

    paths = FleetPaths.from_state_root(tmp_path)

    assert paths.registry == tmp_path / "fleet" / "registry.json"
    assert paths.secrets == tmp_path / "fleet" / "secrets"
    assert paths.limits == tmp_path / "fleet" / "limits.json"
    assert paths.lock == tmp_path / "fleet" / "registry.lock"
    assert paths.recovery == tmp_path / "fleet" / "recovery.json"
    assert paths.mutation_lock == tmp_path / "fleet" / "mutation.lock"


def _account(
    account_id: str = "shared",
    *,
    enabled: bool = True,
    secret_state: SecretState = SecretState.MISSING,
    limit_state: LimitState = LimitState.UNKNOWN,
) -> FleetAccount:
    return FleetAccount(
        account_id,
        "Shared account",
        Provider.GEMINI_API,
        AuthKind.API_KEY,
        secret_state,
        limit_state,
        enabled,
        None,
        None,
        None,
    )


def _series(
    prefix: str = "d",
    *,
    account_id: str | None = "shared",
    enabled: bool = True,
) -> FleetSeries:
    provider = Provider.OLLAMA_LOCAL if account_id is None else Provider.GEMINI_API
    runner = RunnerKind.CODEX_CLI if account_id is None else RunnerKind.GEMINI_CLI
    return FleetSeries(prefix, f"Series {prefix}", 1, runner, provider, "model", account_id, enabled)


def _service(tmp_path: Path, snapshot: FleetSnapshot | None = None):
    from codex_master.fleet_service import FleetPaths, FleetService
    from codex_master.server import build_fleet_private_io

    paths = FleetPaths.from_state_root(tmp_path)
    private_io = build_fleet_private_io(paths)
    private_io = replace(
        private_io,
        utc_now=lambda: datetime(2026, 8, 3, 12, 0, tzinfo=timezone.utc),
    )
    service = FleetService(paths, private_io, pool_root=tmp_path / "pool")
    if snapshot is not None:
        service.commit_snapshot(snapshot, expected_generation=1)
    return service, paths


def _configured_snapshot(*, generation: int = 2) -> FleetSnapshot:
    return FleetSnapshot(
        1,
        generation,
        (_account(secret_state=SecretState.CONFIGURED),),
        (_series(),),
    )


def test_missing_registry_loads_initial_private_layout(tmp_path: Path) -> None:
    service, paths = _service(tmp_path)

    snapshot = service.load()

    assert snapshot == FleetSnapshot(1, 1, (), ())
    assert os.stat(paths.root).st_mode & 0o777 == 0o700
    assert os.stat(paths.secrets).st_mode & 0o777 == 0o700


def test_set_secret_writes_only_private_file_and_public_status(tmp_path: Path) -> None:
    service, paths = _service(tmp_path, FleetSnapshot(1, 2, (_account(),), ()))

    result = service.set_secret("shared", "tiny-secret", expected_generation=2)

    assert result == {"configured": True, "generation": 3}
    assert os.stat(paths.secrets / "shared.secret").st_mode & 0o777 == 0o600
    assert os.stat(paths.registry).st_mode & 0o777 == 0o600
    account = service.load().accounts[0]
    assert account.secret_state is SecretState.CONFIGURED
    assert account.limit_state is LimitState.UNKNOWN


def test_fleet_mutation_lock_is_reentrant_and_private(tmp_path: Path) -> None:
    from codex_master.fleet_service import FleetPaths

    paths = FleetPaths.from_state_root(tmp_path)
    calls: list[tuple[int, str]] = []
    real_flock = fcntl.flock
    lock_ex = getattr(fcntl, "LOCK_EX")
    lock_un = getattr(fcntl, "LOCK_UN")

    def capture_flock(fd: int, operation: int) -> None:
        calls.append((fd, "lock" if operation == lock_ex else "other"))
        if operation == lock_ex:
            return
        real_flock(fd, operation)

    with patch.object(fcntl, "flock", side_effect=capture_flock):
        server_module = __import__("codex_master.server", fromlist=["fleet_mutation_lock"])
        with server_module.fleet_mutation_lock(paths), server_module.fleet_mutation_lock(paths):
            pass

    assert len(calls) == 2
    lock_calls = [op for _, op in calls]
    assert lock_calls == ["lock", "other"]
    assert calls[0][1] != calls[1][1]
    st = paths.mutation_lock.lstat()
    assert stat.S_ISREG(st.st_mode)
    assert st.st_mode & 0o777 == 0o600
    assert st.st_uid == os.getuid()
    assert not paths.mutation_lock.is_symlink()


def test_set_secret_rejects_empty_value(tmp_path: Path) -> None:
    from codex_master.fleet_service import FleetSecretError

    service, paths = _service(tmp_path, FleetSnapshot(1, 2, (_account(),), ()))

    with pytest.raises(FleetSecretError) as raised:
        service.set_secret("shared", "", expected_generation=2)

    assert str(raised.value) == "invalid_secret"
    assert not (paths.secrets / "shared.secret").exists()


def test_set_secret_rejects_value_above_16_kib(tmp_path: Path) -> None:
    from codex_master.fleet_service import FleetSecretError

    service, paths = _service(tmp_path, FleetSnapshot(1, 2, (_account(),), ()))

    with pytest.raises(FleetSecretError) as raised:
        service.set_secret("shared", "x" * (16 * 1024 + 1), expected_generation=2)

    assert str(raised.value) == "invalid_secret"
    assert not (paths.secrets / "shared.secret").exists()


def test_set_secret_accepts_exactly_16_kib(tmp_path: Path) -> None:
    service, paths = _service(tmp_path, FleetSnapshot(1, 2, (_account(),), ()))

    service.set_secret("shared", "x" * (16 * 1024), expected_generation=2)

    assert (paths.secrets / "shared.secret").stat().st_size == 16 * 1024


def test_generation_conflict_does_not_overwrite_secret(tmp_path: Path) -> None:
    from codex_master.fleet_service import FleetConflictError

    service, paths = _service(tmp_path, FleetSnapshot(1, 2, (_account(),), ()))
    service.set_secret("shared", "first", expected_generation=2)

    with pytest.raises(FleetConflictError):
        service.set_secret("shared", "second", expected_generation=2)

    assert (paths.secrets / "shared.secret").read_text() == "first"


def test_account_id_cannot_escape_secret_directory(tmp_path: Path) -> None:
    from codex_master.fleet_service import FleetSecretError

    service, _ = _service(tmp_path, FleetSnapshot(1, 2, (_account(),), ()))

    with pytest.raises(FleetSecretError):
        service.set_secret("../outside", "tiny", expected_generation=2)

    assert not (tmp_path / "outside.secret").exists()


@pytest.mark.parametrize("link_kind", ["symlink", "hardlink"])
def test_set_secret_rejects_link_targets(tmp_path: Path, link_kind: str) -> None:
    from codex_master.fleet_service import FleetSecretError

    service, paths = _service(tmp_path, FleetSnapshot(1, 2, (_account(),), ()))
    service.load()
    target = tmp_path / "target"
    target.write_text("untouched")
    secret_path = paths.secrets / "shared.secret"
    if link_kind == "symlink":
        secret_path.symlink_to(target)
    else:
        os.link(target, secret_path)

    with pytest.raises(FleetSecretError):
        service.set_secret("shared", "replacement", expected_generation=2)

    assert target.read_text() == "untouched"


def test_secret_fragment_never_appears_in_exception(tmp_path: Path) -> None:
    from codex_master.fleet_service import FleetSecretError

    fragment = "SYNTHETIC-TOKEN-FRAGMENT"
    service, _ = _service(tmp_path, FleetSnapshot(1, 2, (_account(),), ()))

    with pytest.raises(FleetSecretError) as raised:
        service.set_secret("shared", fragment * 1000, expected_generation=2)

    assert fragment not in str(raised.value)
    assert fragment not in repr(raised.value)


def test_commit_rejects_stale_generation(tmp_path: Path) -> None:
    from codex_master.fleet_service import FleetConflictError

    service, _ = _service(tmp_path)
    current = service.load()
    next_snapshot = FleetSnapshot(1, 2, (_account(),), ())
    service.commit_snapshot(next_snapshot, expected_generation=current.generation)

    with pytest.raises(FleetConflictError):
        service.commit_snapshot(next_snapshot, expected_generation=current.generation)


def test_mark_limited_writes_private_journal_before_registry(tmp_path: Path) -> None:
    from codex_master.fleet_service import FleetService
    from codex_master.server import build_fleet_private_io

    service, paths = _service(tmp_path, _configured_snapshot())
    real_io = build_fleet_private_io(paths)

    def fail_registry(path: Path, text: str) -> None:
        if path == paths.registry:
            raise RuntimeError("synthetic_registry_failure")
        real_io.replace_text(path, text)

    failing = FleetService(
        paths,
        replace(real_io, replace_text=fail_registry),
        pool_root=tmp_path / "pool",
    )

    with pytest.raises(RuntimeError, match="synthetic_registry_failure"):
        failing.mark_limited("shared", reset_at_utc=None, reason="provider_429")

    account = service.load().accounts[0]
    assert service.load().generation == 2
    assert account.limit_state is LimitState.LIMITED
    assert account.limit_reason == "provider_429"
    assert os.stat(paths.limits).st_mode & 0o777 == 0o600


def test_mark_limited_validates_before_writing_journal(tmp_path: Path) -> None:
    service, paths = _service(tmp_path, _configured_snapshot())

    with pytest.raises(ValueError):
        service.mark_limited("shared", reset_at_utc=None, reason="invalid reason")

    assert not paths.limits.exists()
    assert service.load() == _configured_snapshot()


def test_successful_probe_writes_ready_before_clearing_journal(tmp_path: Path) -> None:
    import json

    from codex_master.fleet_service import FleetService
    from codex_master.server import build_fleet_private_io

    service, paths = _service(tmp_path, _configured_snapshot())
    limited = service.mark_limited("shared", reset_at_utc=None, reason="provider_429")
    real_io = build_fleet_private_io(paths)

    def fail_limit_clear(path: Path, text: str) -> None:
        if path == paths.limits:
            raise RuntimeError("synthetic_limit_clear_failure")
        real_io.replace_text(path, text)

    failing = FleetService(
        paths,
        replace(
            real_io,
            replace_text=fail_limit_clear,
            utc_now=lambda: datetime(2026, 8, 3, 12, 0, tzinfo=timezone.utc),
        ),
        pool_root=tmp_path / "pool",
    )

    with pytest.raises(RuntimeError, match="synthetic_limit_clear_failure"):
        failing.probe_account(
            "shared",
            lambda account: ProbeResult(account.provider, True, "model", True, None),
            expected_generation=limited.generation,
        )

    raw_registry = json.loads(paths.registry.read_text())
    assert raw_registry["accounts"][0]["limit_state"] == "ready"
    assert service.load().accounts[0].limit_state is LimitState.LIMITED


def test_one_limited_account_blocks_every_bound_series(tmp_path: Path) -> None:
    snapshot = FleetSnapshot(
        1,
        2,
        (_account(secret_state=SecretState.CONFIGURED),),
        (
            _series("d"),
            _series("e"),
            _series("f", account_id=None),
        ),
    )
    service, _ = _service(tmp_path, snapshot)

    service.mark_limited(
        "shared",
        reset_at_utc="2026-08-04T00:00:00Z",
        reason="provider_429",
    )

    assert service.account_gate("d1").reason == "limit_active"
    assert service.account_gate("e1").reason == "limit_active"
    assert service.account_gate("f1").reason == "ready"


@pytest.mark.parametrize(
    ("account", "series", "want"),
    [
        (_account(enabled=False, secret_state=SecretState.CONFIGURED), _series(), "account_disabled"),
        (_account(), _series(), "secret_missing"),
        (_account(secret_state=SecretState.INVALID), _series(), "auth_invalid"),
        (
            _account(secret_state=SecretState.CONFIGURED, limit_state=LimitState.UNKNOWN),
            _series(),
            "limit_unknown",
        ),
        (
            replace(
                _account(secret_state=SecretState.CONFIGURED, limit_state=LimitState.READY),
                limit_reason="provider_unavailable",
            ),
            _series(),
            "provider_unavailable",
        ),
        (
            replace(
                _account(secret_state=SecretState.CONFIGURED, limit_state=LimitState.READY),
                limit_reason="model_unavailable",
            ),
            _series(),
            "model_unavailable",
        ),
        (
            replace(
                _account(secret_state=SecretState.CONFIGURED, limit_state=LimitState.READY),
                last_probe_at_utc="2026-08-03T11:44:59Z",
            ),
            _series(),
            "probe_stale",
        ),
        (
            replace(
                _account(secret_state=SecretState.CONFIGURED, limit_state=LimitState.READY),
                last_probe_at_utc="2026-08-03T11:45:00Z",
            ),
            _series(),
            "ready",
        ),
    ],
)
def test_account_gate_uses_fixed_priority_codes(
    tmp_path: Path,
    account: FleetAccount,
    series: FleetSeries,
    want: str,
) -> None:
    service, _ = _service(tmp_path, FleetSnapshot(1, 2, (account,), (series,)))

    decision = service.account_gate("d1")

    assert decision.allowed is (want == "ready")
    assert decision.reason == want
    assert decision.account_id == "shared"
    assert decision.generation == 2


@pytest.mark.parametrize(
    ("account", "want"),
    [
        (_account(), "secret_missing"),
        (
            _account(
                secret_state=SecretState.CONFIGURED,
                limit_state=LimitState.LIMITED,
            ),
            "limit_active",
        ),
        (
            replace(
                _account(
                    secret_state=SecretState.CONFIGURED,
                    limit_state=LimitState.READY,
                ),
                last_probe_at_utc="2026-08-03T11:44:59Z",
            ),
            "probe_stale",
        ),
    ],
)
def test_series_gate_rejects_unready_account_bound_candidate(
    tmp_path: Path,
    account: FleetAccount,
    want: str,
) -> None:
    service, _ = _service(tmp_path, FleetSnapshot(1, 2, (account,), ()))

    decision = service.series_gate(_series())

    assert decision.allowed is False
    assert decision.reason == want
    assert decision.account_id == "shared"
    assert decision.generation == 2


def test_series_gate_allows_accountless_ollama_and_marks_disabled_series(
    tmp_path: Path,
) -> None:
    service, _ = _service(tmp_path)

    ollama = service.series_gate(_series(account_id=None))
    disabled = service.series_gate(_series(account_id=None, enabled=False))

    assert ollama.allowed is True
    assert ollama.reason == "ready"
    assert ollama.account_id is None
    assert disabled.allowed is False
    assert disabled.reason == "series_disabled"
    assert disabled.account_id is None
    assert {ollama.generation, disabled.generation} == {1}


@pytest.mark.parametrize(
    ("provider", "runner", "allowed", "reason"),
    [
        (Provider.GEMINI_API, RunnerKind.GEMINI_CLI, False, "account_required"),
        (Provider.OPENAI_API, RunnerKind.CODEX_CLI, False, "account_required"),
        (Provider.HUGGINGFACE_INFERENCE, RunnerKind.CODEX_CLI, False, "account_required"),
        (Provider.OLLAMA_LOCAL, RunnerKind.CODEX_CLI, True, "ready"),
    ],
)
def test_series_gate_allows_accountless_series_only_for_local_ollama(
    tmp_path: Path,
    provider: Provider,
    runner: RunnerKind,
    allowed: bool,
    reason: str,
) -> None:
    service, _ = _service(tmp_path)
    candidate = replace(_series(account_id=None), provider=provider, runner=runner)

    decision = service.series_gate(candidate)

    assert decision.allowed is allowed
    assert decision.reason == reason


def test_series_gate_rejects_candidate_account_provider_mismatch(tmp_path: Path) -> None:
    service, _ = _service(tmp_path, FleetSnapshot(1, 2, (_account(),), ()))
    candidate = replace(
        _series(),
        runner=RunnerKind.CODEX_CLI,
        provider=Provider.OPENAI_API,
    )

    decision = service.series_gate(candidate)

    assert decision.allowed is False
    assert decision.reason == "account_provider_mismatch"
    assert decision.account_id == "shared"
    assert decision.generation == 2


def test_disabled_or_unknown_series_fails_closed(tmp_path: Path) -> None:
    service, _ = _service(
        tmp_path,
        FleetSnapshot(
            1,
            2,
            (_account(secret_state=SecretState.CONFIGURED),),
            (_series(enabled=False),),
        ),
    )

    assert service.account_gate("d1").reason == "account_disabled"
    assert service.account_gate("z1").reason == "account_disabled"


def test_known_reset_time_never_unlocks_without_probe(tmp_path: Path) -> None:
    service, _ = _service(tmp_path, _configured_snapshot())
    service.mark_limited(
        "shared",
        reset_at_utc="2026-08-03T11:00:00Z",
        reason="provider_429",
    )

    decision = service.account_gate("d1")

    assert decision.allowed is False
    assert decision.reason == "limit_active"


def test_backward_clock_jump_never_makes_future_probe_ready(tmp_path: Path) -> None:
    account = replace(
        _account(secret_state=SecretState.CONFIGURED, limit_state=LimitState.READY),
        last_probe_at_utc="2026-08-03T13:00:00Z",
    )
    service, _ = _service(tmp_path, FleetSnapshot(1, 2, (account,), (_series(),)))

    decision = service.account_gate("d1")

    assert decision.allowed is False
    assert decision.reason == "probe_stale"


def test_probe_runs_without_registry_lock_and_sets_ready(tmp_path: Path) -> None:
    from codex_master.fleet_service import FleetService
    from codex_master.server import build_fleet_private_io

    service, paths = _service(tmp_path, _configured_snapshot())
    real_io = build_fleet_private_io(paths)
    held = False

    @contextmanager
    def observed_lock():
        nonlocal held
        assert held is False
        held = True
        try:
            with real_io.lock():
                yield
        finally:
            held = False

    observed = FleetService(
        paths,
        replace(
            real_io,
            lock=observed_lock,
            utc_now=lambda: datetime(2026, 8, 3, 12, 0, tzinfo=timezone.utc),
        ),
        pool_root=tmp_path / "pool",
    )

    def probe(account: FleetAccount) -> ProbeResult:
        assert held is False
        return ProbeResult(account.provider, True, "model", True, None)

    result = observed.probe_account("shared", probe, expected_generation=2)

    assert result == {"probed": True, "generation": 3, "ready": True, "reason": "ready"}
    assert observed.account_gate("d1").reason == "ready"


def test_probe_rejects_generation_change_while_external_call_runs(tmp_path: Path) -> None:
    from codex_master.fleet_service import FleetConflictError

    service, _ = _service(tmp_path, _configured_snapshot())

    def probe(account: FleetAccount) -> ProbeResult:
        service.mark_limited(account.account_id, reset_at_utc=None, reason="provider_429")
        return ProbeResult(account.provider, True, "model", True, None)

    with pytest.raises(FleetConflictError):
        service.probe_account("shared", probe, expected_generation=2)

    assert service.account_gate("d1").reason == "limit_active"


@pytest.mark.parametrize(
    ("kind", "want", "secret_state"),
    [
        ("account_limited", "limit_active", SecretState.CONFIGURED),
        ("auth_invalid", "auth_invalid", SecretState.INVALID),
        ("provider_unavailable", "provider_unavailable", SecretState.CONFIGURED),
        ("model_unavailable", "model_unavailable", SecretState.CONFIGURED),
        ("runner_failed", "provider_unavailable", SecretState.CONFIGURED),
    ],
)
def test_probe_errors_become_fixed_gate_reasons(
    tmp_path: Path,
    kind: str,
    want: str,
    secret_state: SecretState,
) -> None:
    service, _ = _service(tmp_path, _configured_snapshot())
    error = ProviderError(kind, True, 429, None)  # type: ignore[arg-type]

    result = service.probe_account(
        "shared",
        lambda account: ProbeResult(account.provider, False, "model", False, error),
        expected_generation=2,
    )

    assert result["reason"] == want
    assert service.load().accounts[0].secret_state is secret_state
    assert service.account_gate("d1").reason == want


def test_probe_exception_is_fully_redacted_from_public_result(tmp_path: Path) -> None:
    service, _ = _service(tmp_path, _configured_snapshot())

    def failing_probe(account: FleetAccount) -> ProbeResult:
        raise RuntimeError("SYNTHETIC-KEY /private/path backend-value")

    result = service.probe_account("shared", failing_probe, expected_generation=2)
    public = service.public_snapshot()
    rendered = repr((result, public))

    assert result["reason"] == "provider_unavailable"
    assert "SYNTHETIC-KEY" not in rendered
    assert "/private/path" not in rendered
    assert "backend-value" not in rendered


def test_server_adapters_distinguish_missing_from_unsafe_files(tmp_path: Path) -> None:
    from codex_master.fleet_service import FleetPaths
    from codex_master.server import AgentError, build_fleet_private_io

    paths = FleetPaths.from_state_root(tmp_path)
    io = build_fleet_private_io(paths)
    io.ensure_dir(paths.root)
    io.ensure_dir(paths.secrets)

    assert io.read_text(paths.registry, 1024, "registry_error") is None
    assert io.read_bytes(paths.secrets / "missing.secret", 1024, "secret_error") is None

    target = tmp_path / "target"
    target.write_text("data")
    paths.registry.symlink_to(target)
    with pytest.raises(AgentError, match="registry_error"):
        io.read_text(paths.registry, 1024, "registry_error")


def test_server_registry_lock_is_reentrant_and_private(tmp_path: Path) -> None:
    from codex_master.fleet_service import FleetPaths
    from codex_master.server import build_fleet_private_io

    paths = FleetPaths.from_state_root(tmp_path)
    io = build_fleet_private_io(paths)

    with io.lock():
        with io.lock():
            assert os.stat(paths.lock).st_mode & 0o777 == 0o600


@pytest.mark.parametrize("reader", ["text", "bytes"])
def test_optional_private_read_rejects_missing_parent(tmp_path: Path, reader: str) -> None:
    from codex_master.fleet_service import FleetPaths
    from codex_master.server import AgentError, build_fleet_private_io

    paths = FleetPaths.from_state_root(tmp_path)
    io = build_fleet_private_io(paths)
    target = tmp_path / "missing-parent" / "target"

    with pytest.raises(AgentError, match="read_error"):
        if reader == "text":
            io.read_text(target, 1024, "read_error")
        else:
            io.read_bytes(target, 1024, "read_error")


@pytest.mark.parametrize("reader", ["text", "bytes"])
def test_optional_private_read_rejects_parent_swap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    reader: str,
) -> None:
    from codex_master import server
    from codex_master.fleet_service import FleetPaths

    paths = FleetPaths.from_state_root(tmp_path)
    io = server.build_fleet_private_io(paths)
    io.ensure_dir(paths.root)
    io.replace_text(paths.registry, "before")
    moved = tmp_path / "moved-fleet"
    function_name = "read_private_regular_text" if reader == "text" else "pool_read_private_bytes"
    real_read = getattr(server, function_name)

    def swap_parent_then_read(
        path: Path,
        max_bytes: int,
        error_text: str,
        *,
        expected_parent_stat=None,
        expected_target_stat=None,
    ):
        os.rename(paths.root, moved)
        io.ensure_dir(paths.root)
        paths.registry.write_text("after")
        return real_read(
            path,
            max_bytes,
            error_text,
            expected_parent_stat=expected_parent_stat,
            expected_target_stat=expected_target_stat,
        )

    monkeypatch.setattr(server, function_name, swap_parent_then_read)

    with pytest.raises(server.AgentError, match="read_error"):
        if reader == "text":
            io.read_text(paths.registry, 1024, "read_error")
        else:
            io.read_bytes(paths.registry, 1024, "read_error")


@pytest.mark.parametrize("reader", ["text", "bytes"])
def test_optional_private_read_rejects_target_swap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    reader: str,
) -> None:
    from codex_master import server
    from codex_master.fleet_service import FleetPaths

    paths = FleetPaths.from_state_root(tmp_path)
    io = server.build_fleet_private_io(paths)
    io.ensure_dir(paths.root)
    io.replace_text(paths.registry, "before")
    replacement = tmp_path / "replacement"
    replacement.write_text("after")
    function_name = "read_private_regular_text" if reader == "text" else "pool_read_private_bytes"
    real_read = getattr(server, function_name)

    def swap_target_then_read(
        path: Path,
        max_bytes: int,
        error_text: str,
        *,
        expected_parent_stat=None,
        expected_target_stat=None,
    ):
        os.replace(replacement, paths.registry)
        return real_read(
            path,
            max_bytes,
            error_text,
            expected_parent_stat=expected_parent_stat,
            expected_target_stat=expected_target_stat,
        )

    monkeypatch.setattr(server, function_name, swap_target_then_read)

    with pytest.raises(server.AgentError, match="read_error"):
        if reader == "text":
            io.read_text(paths.registry, 1024, "read_error")
        else:
            io.read_bytes(paths.registry, 1024, "read_error")


def test_private_replace_rejects_hardlink_added_during_write(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from codex_master import server
    from codex_master.fleet_service import FleetPaths

    paths = FleetPaths.from_state_root(tmp_path)
    io = server.build_fleet_private_io(paths)
    io.ensure_dir(paths.root)
    io.replace_text(paths.registry, "before")
    alias = paths.root / "registry-alias"
    real_write = server.write_private_new_bytes

    def add_hardlink_then_write(
        path: Path,
        data: bytes,
        mode: int = 0o600,
        *,
        dir_fd: int | None = None,
    ) -> None:
        os.link(paths.registry, alias)
        real_write(path, data, mode=mode, dir_fd=dir_fd)

    monkeypatch.setattr(server, "write_private_new_bytes", add_hardlink_then_write)

    with pytest.raises(server.AgentError, match="private state path changed unexpectedly"):
        io.replace_text(paths.registry, "after")

    assert paths.registry.read_text() == "before"
    assert alias.read_text() == "before"


def test_fleet_paths_repr_redacts_private_paths(tmp_path: Path) -> None:
    from codex_master.fleet_service import FleetPaths

    paths = FleetPaths.from_state_root(tmp_path / "private-state")
    rendered = repr(paths)

    assert all(
        str(path) not in rendered
        for path in (
            paths.root,
            paths.registry,
            paths.secrets,
            paths.limits,
            paths.lock,
        )
    )
