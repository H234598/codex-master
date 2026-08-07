from __future__ import annotations

import os
import threading
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
    assert paths.rate_limits == tmp_path / "fleet" / "rate-limits.json"
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
    return FleetAccount(account_id, "Shared account", Provider.GEMINI_API, AuthKind.API_KEY,
                        secret_state, limit_state, enabled, None, None, None)


def _series(prefix: str = "d", *, account_id: str | None = "shared", enabled: bool = True) -> FleetSeries:
    provider = Provider.OLLAMA_LOCAL if account_id is None else Provider.GEMINI_API
    runner = RunnerKind.CODEX_CLI if account_id is None else RunnerKind.GEMINI_CLI
    return FleetSeries(prefix, f"Series {prefix}", 1, runner, provider, "model", account_id, enabled)


def _service(tmp_path: Path, snapshot: FleetSnapshot | None = None):
    from codex_master.fleet_service import FleetPaths, FleetService
    from codex_master.server import build_fleet_private_io

    paths = FleetPaths.from_state_root(tmp_path)
    private_io = replace(
        build_fleet_private_io(paths),
        utc_now=lambda: datetime(2026, 8, 3, 12, 0, tzinfo=timezone.utc),
    )
    service = FleetService(paths, private_io, pool_root=tmp_path / "pool")
    if snapshot is not None:
        service.commit_snapshot(snapshot, expected_generation=1)
    return service, paths


def _configured_snapshot(*, generation: int = 2) -> FleetSnapshot:
    return FleetSnapshot(1, generation, (_account(secret_state=SecretState.CONFIGURED),), (_series(),))


def test_missing_registry_loads_initial_private_layout(tmp_path: Path) -> None:
    service, paths = _service(tmp_path)
    assert service.load() == FleetSnapshot(1, 1, (), ())
    assert os.stat(paths.root).st_mode & 0o777 == 0o700
    assert os.stat(paths.secrets).st_mode & 0o777 == 0o700


def test_set_secret_writes_only_private_file_and_public_status(tmp_path: Path) -> None:
    service, paths = _service(tmp_path, FleetSnapshot(1, 2, (_account(),), ()))
    result = service.set_secret("shared", "tiny-secret", expected_generation=2)
    assert result == {"configured": True, "generation": 3}
    assert os.stat(paths.secrets / "shared.secret").st_mode & 0o777 == 0o600
    assert os.stat(paths.registry).st_mode & 0o777 == 0o600
    assert service.load().accounts[0].secret_state is SecretState.CONFIGURED
    assert "tiny-secret" not in repr(service.public_snapshot())


@pytest.mark.parametrize("secret", ["", "x" * (16 * 1024 + 1)])
def test_set_secret_rejects_invalid_size(tmp_path: Path, secret: str) -> None:
    from codex_master.fleet_service import FleetSecretError

    service, paths = _service(tmp_path, FleetSnapshot(1, 2, (_account(),), ()))
    with pytest.raises(FleetSecretError) as raised:
        service.set_secret("shared", secret, expected_generation=2)
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

    service, paths = _service(tmp_path, FleetSnapshot(1, 2, (_account(),), ()))
    with pytest.raises(FleetSecretError):
        service.set_secret("../outside", "tiny", expected_generation=2)
    assert not (paths.secrets.parent / "outside.secret").exists()
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


def test_commit_rejects_stale_generation(tmp_path: Path) -> None:
    from codex_master.fleet_service import FleetConflictError

    service, _ = _service(tmp_path)
    current = service.load()
    next_snapshot = FleetSnapshot(1, 2, (_account(),), ())
    service.commit_snapshot(next_snapshot, expected_generation=current.generation)

    with pytest.raises(FleetConflictError):
        service.commit_snapshot(next_snapshot, expected_generation=current.generation)


def test_mark_limited_overlays_shared_account_gate(tmp_path: Path) -> None:
    snapshot = FleetSnapshot(1, 2, (_account(secret_state=SecretState.CONFIGURED),),
                             (_series("d"), _series("e"), _series("f", account_id=None)))
    service, _ = _service(tmp_path, snapshot)
    service.mark_limited("shared", reset_at_utc="2026-08-04T00:00:00Z", reason="provider_429")
    assert service.account_gate("d1").reason == "limit_active"
    assert service.account_gate("e1").reason == "limit_active"
    assert service.account_gate("f1").reason == "ready"


def test_known_reset_time_expires_to_unknown_without_probe(tmp_path: Path) -> None:
    service, _ = _service(tmp_path, _configured_snapshot())
    service.mark_limited("shared", reset_at_utc="2026-08-03T11:00:00Z", reason="provider_429")
    assert service.account_gate("d1").reason == "limit_unknown"


def test_invalid_limit_sidecar_is_quarantined_and_fail_closed(tmp_path: Path) -> None:
    service, paths = _service(tmp_path, _configured_snapshot())
    paths.limits.write_text("{invalid", encoding="utf-8")

    assert service.account_gate("d1").reason == "limit_unknown"
    marker = paths.recovery.with_name("limits.recovery.json")
    assert marker.exists()
    assert "invalid_fleet_limits" in marker.read_text(encoding="utf-8")


def test_gemini_rate_reservation_blocks_bursts_across_service_instances(tmp_path: Path) -> None:
    from codex_master.fleet_service import FleetRateLimitError

    service, paths = _service(tmp_path, _configured_snapshot())
    reservation = service.reserve_gemini_request("shared")
    assert reservation.account_id == "shared"
    assert paths.rate_limits.exists()

    with pytest.raises(FleetRateLimitError) as raised:
        type(service)(paths, service._io, pool_root=tmp_path / "pool").reserve_gemini_request("shared")

    assert raised.value.reason == "gemini_local_rate_limit"
    assert raised.value.retry_after_seconds >= 60
    assert reservation.reservation_id in paths.rate_limits.read_text(encoding="utf-8")


def test_gemini_rate_reservation_applies_exponential_429_cooldown(tmp_path: Path) -> None:
    from codex_master.fleet_service import FleetRateLimitError

    service, paths = _service(tmp_path, _configured_snapshot())
    reservation = service.reserve_gemini_request("shared")
    service.release_gemini_request(reservation, outcome="rate_limited")

    with pytest.raises(FleetRateLimitError) as raised:
        service.reserve_gemini_request("shared")

    assert raised.value.retry_after_seconds >= 15 * 60
    assert '"in_flight": null' in paths.rate_limits.read_text(encoding="utf-8")


def test_invalid_gemini_rate_state_fails_closed(tmp_path: Path) -> None:
    from codex_master.fleet_service import FleetRateLimitError

    service, paths = _service(tmp_path, _configured_snapshot())
    paths.rate_limits.write_text("{invalid", encoding="utf-8")

    with pytest.raises(ValueError, match="invalid_gemini_rate_limits"):
        service.reserve_gemini_request("shared")

    marker = paths.recovery.with_name("rate-limits.recovery.json")
    assert marker.exists()


@pytest.mark.parametrize(
    ("account", "want"),
    [
        (_account(enabled=False, secret_state=SecretState.CONFIGURED), "account_disabled"),
        (_account(), "secret_missing"),
        (_account(secret_state=SecretState.INVALID), "auth_invalid"),
        (_account(secret_state=SecretState.CONFIGURED, limit_state=LimitState.UNKNOWN), "limit_unknown"),
        (replace(_account(secret_state=SecretState.CONFIGURED, limit_state=LimitState.READY),
                 limit_reason="provider_unavailable"), "provider_unavailable"),
        (replace(_account(secret_state=SecretState.CONFIGURED, limit_state=LimitState.READY),
                 limit_reason="model_unavailable"), "model_unavailable"),
        (replace(_account(secret_state=SecretState.CONFIGURED, limit_state=LimitState.READY),
                 last_probe_at_utc="2026-08-03T11:44:59Z"), "probe_stale"),
        (replace(_account(secret_state=SecretState.CONFIGURED, limit_state=LimitState.READY),
                 last_probe_at_utc="2026-08-03T11:45:00Z"), "ready"),
    ],
)
def test_account_gate_uses_fixed_priority_codes(tmp_path: Path, account: FleetAccount, want: str) -> None:
    service, _ = _service(tmp_path, FleetSnapshot(1, 2, (account,), (_series(),)))
    decision = service.account_gate("d1")
    assert decision.allowed is (want == "ready")
    assert decision.reason == want
    assert decision.account_id == "shared"
    assert decision.generation == 2


def test_series_gate_allows_accountless_ollama_and_rejects_disabled(tmp_path: Path) -> None:
    service, _ = _service(tmp_path)
    ollama = service.series_gate(_series(account_id=None))
    disabled = service.series_gate(_series(account_id=None, enabled=False))
    assert ollama == type(ollama)(True, "ready", None, 1)
    assert disabled == type(disabled)(False, "series_disabled", None, 1)


def test_probe_runs_without_registry_lock_and_sets_ready(tmp_path: Path) -> None:
    service, paths = _service(tmp_path, _configured_snapshot())
    real_io = service._io
    held = False
    held_during_probe: list[bool] = []

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

    observed = type(service)(paths, replace(real_io, lock=observed_lock), pool_root=tmp_path / "pool")

    def probe(account: FleetAccount) -> ProbeResult:
        held_during_probe.append(held)
        return ProbeResult(account.provider, True, "model", True, None)

    result = observed.probe_account("shared", probe, expected_generation=2)
    assert held_during_probe == [False]
    assert result == {
        "probed": True,
        "generation": 3,
        "ready": True,
        "reason": "ready",
        "model": "model",
    }
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
        ("secret_missing", "secret_missing", SecretState.MISSING),
        ("provider_unavailable", "provider_unavailable", SecretState.CONFIGURED),
        ("model_unavailable", "model_unavailable", SecretState.CONFIGURED),
        ("runner_failed", "provider_unavailable", SecretState.CONFIGURED),
    ],
)
def test_probe_errors_become_fixed_gate_reasons(tmp_path: Path, kind: str, want: str,
                                                secret_state: SecretState) -> None:
    service, _ = _service(tmp_path, _configured_snapshot())
    error = ProviderError(kind, True, 429, None)  # type: ignore[arg-type]
    result = service.probe_account(
        "shared", lambda account: ProbeResult(account.provider, False, "model", False, error),
        expected_generation=2,
    )
    assert result["reason"] == want
    assert service.load().accounts[0].secret_state is secret_state
    assert service.account_gate("d1").reason == want


def test_probe_exception_is_redacted_from_public_result(tmp_path: Path) -> None:
    service, _ = _service(tmp_path, _configured_snapshot())

    def failing_probe(account: FleetAccount) -> ProbeResult:
        raise RuntimeError("SYNTHETIC-KEY /private/path backend-value")

    result = service.probe_account("shared", failing_probe, expected_generation=2)
    rendered = repr((result, service.public_snapshot()))
    assert result["reason"] == "provider_unavailable"
    assert "SYNTHETIC-KEY" not in rendered
    assert "/private/path" not in rendered
    assert "backend-value" not in rendered


def test_private_io_distinguishes_missing_from_unsafe_files(tmp_path: Path) -> None:
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


@pytest.mark.parametrize("kind", ["text", "bytes"])
@pytest.mark.parametrize("link_kind", ["symlink", "hardlink"])
def test_private_io_rejects_symlink_and_hardlink_writes(
    tmp_path: Path, kind: str, link_kind: str
) -> None:
    from codex_master.fleet_service import FleetPaths
    from codex_master.server import AgentError, build_fleet_private_io

    paths = FleetPaths.from_state_root(tmp_path)
    io = build_fleet_private_io(paths)
    io.ensure_dir(paths.root)
    target = tmp_path / "target"
    target.write_text("untouched")
    target_path = paths.registry
    if link_kind == "symlink":
        target_path.symlink_to(target)
    else:
        os.link(target, target_path)
    with pytest.raises(AgentError):
        if kind == "text":
            io.replace_text(target_path, "changed")
        else:
            io.replace_bytes(target_path, b"changed", 0o600)
    assert target.read_text() == "untouched"


def test_private_lock_is_reentrant_and_redacts_paths(tmp_path: Path) -> None:
    from codex_master.fleet_service import FleetPaths
    from codex_master.server import build_fleet_private_io

    paths = FleetPaths.from_state_root(tmp_path / "private-state")
    io = build_fleet_private_io(paths)
    with io.lock():
        with io.lock():
            assert os.stat(paths.lock).st_mode & 0o777 == 0o600
    assert all(str(path) not in repr(paths) for path in
               (paths.root, paths.registry, paths.secrets, paths.limits, paths.lock))


def test_private_lock_serializes_cross_thread_registry_access(tmp_path: Path) -> None:
    from codex_master.fleet_service import FleetPaths
    from codex_master.server import build_fleet_private_io

    io = build_fleet_private_io(FleetPaths.from_state_root(tmp_path / "private-state"))
    first_entered = threading.Event()
    release_first = threading.Event()
    second_entered = threading.Event()

    def first() -> None:
        with io.lock():
            first_entered.set()
            release_first.wait(2)

    def second() -> None:
        first_entered.wait(1)
        with io.lock():
            second_entered.set()

    first_thread = threading.Thread(target=first)
    second_thread = threading.Thread(target=second)
    first_thread.start()
    assert first_entered.wait(1)
    second_thread.start()
    assert not second_entered.wait(0.05)
    release_first.set()
    first_thread.join(2)
    second_thread.join(2)
    assert not first_thread.is_alive()
    assert not second_thread.is_alive()
    assert second_entered.is_set()
