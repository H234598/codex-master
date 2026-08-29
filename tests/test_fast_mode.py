from __future__ import annotations

import json
import multiprocessing
import os
import stat
import sys
import types
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from codex_master import fast_mode


NOW = datetime(2026, 8, 23, 12, 0, tzinfo=timezone.utc)


@pytest.fixture
def configured_fast_mode(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> dict[str, object]:
    clock = {"now": NOW}
    notifications: list[dict[str, object]] = []
    snapshots: dict[str, object] = {}
    state_root = tmp_path / "state-root"
    state_root.mkdir(mode=0o700)
    state_path = state_root / "private" / "fast-mode.json"
    monkeypatch.setattr(fast_mode, "_STATE_ROOT", state_root, raising=False)
    monkeypatch.setattr(fast_mode, "_STATE_PATH", state_path)
    monkeypatch.setattr(fast_mode, "_now_utc", lambda: clock["now"])
    monkeypatch.setattr(fast_mode, "_snapshot_reader", lambda account: snapshots.get(account))
    monkeypatch.setattr(fast_mode, "_notifier", notifications.append)
    return {
        "clock": clock,
        "notifications": notifications,
        "snapshots": snapshots,
        "state_path": state_path,
        "state_root": state_root,
    }


def exhausted_snapshot(account: str) -> dict[str, object]:
    return {"schema_version": 1, "account": account, "exhausted": True}


def _race_worker(
    state_root: str,
    state_path: str,
    action: str,
    account: str,
    now_text: str,
    start: multiprocessing.synchronize.Barrier,
    results: multiprocessing.queues.Queue,
) -> None:
    from codex_master import fast_mode as child_fast_mode

    now = datetime.fromisoformat(now_text)
    child_fast_mode._STATE_ROOT = Path(state_root)
    child_fast_mode._STATE_PATH = Path(state_path)
    child_fast_mode._snapshot_reader = lambda _account: None
    child_fast_mode._notifier = lambda _payload: None
    child_fast_mode._now_utc = lambda: now
    try:
        start.wait(timeout=5)
        if action == "enable":
            child_fast_mode.set_mode(account, enabled=True)
        elif action == "disable":
            child_fast_mode.set_mode(account, enabled=False)
        elif action == "expire":
            child_fast_mode.active_mode(account)
        elif action == "remind":
            child_fast_mode.maybe_notify_fast(account, now=now)
        else:
            raise AssertionError(f"unexpected action: {action}")
    except Exception as exc:
        results.put(("error", str(exc)[:80]))
    else:
        results.put(("ok", action))


def _run_race(
    monkeypatch: pytest.MonkeyPatch,
    state_root: Path,
    state_path: Path,
    actions: tuple[tuple[str, str, datetime], ...],
) -> None:
    try:
        context = multiprocessing.get_context("fork")
    except ValueError:
        pytest.skip("Fast-mode locking is POSIX-only")
    monkeypatch.setattr(fast_mode, "_STATE_ROOT", state_root, raising=False)
    monkeypatch.setattr(fast_mode, "_STATE_PATH", state_path)
    barrier = context.Barrier(len(actions), timeout=5)
    results = context.Queue()
    processes = [
        context.Process(
            target=_race_worker,
            args=(
                str(state_root),
                str(state_path),
                action,
                account,
                now.isoformat(),
                barrier,
                results,
            ),
        )
        for action, account, now in actions
    ]
    for process in processes:
        process.start()
    for process in processes:
        process.join(timeout=10)
        assert process.exitcode == 0
    assert sorted(results.get(timeout=2) for _ in processes) == sorted(("ok", action) for action, _account, _now in actions)


def test_initial_state_is_flex_and_snapshot_is_empty(configured_fast_mode: dict[str, object]) -> None:
    assert fast_mode.active_mode("BW_Work") is None
    assert fast_mode.snapshot() == {"schema_version": 1, "modes": {}}


def test_enable_persists_private_redacted_account_mode_and_notifies(
    configured_fast_mode: dict[str, object],
) -> None:
    until = "2026-08-23T13:00:00Z"

    result = fast_mode.set_mode(
        "BW_Work",
        enabled=True,
        reason="Bearer super-secret must never persist",
        until_utc=until,
    )

    assert result == {
        "account": "BW_Work",
        "state": "fast",
        "reason": "operator_request",
        "until_utc": until,
    }
    assert fast_mode.active_mode("BW_Work") == result
    state_path = configured_fast_mode["state_path"]
    assert isinstance(state_path, Path)
    raw = state_path.read_text(encoding="utf-8")
    assert "super-secret" not in raw
    assert stat.S_IMODE(state_path.stat().st_mode) == 0o600
    assert stat.S_IMODE(state_path.parent.stat().st_mode) == 0o700
    notifications = configured_fast_mode["notifications"]
    assert notifications == [{"account": "BW_Work", "state": "fast", "reason": "operator_request"}]


def test_disable_returns_only_target_account_to_flex(configured_fast_mode: dict[str, object]) -> None:
    fast_mode.set_mode("BW_Work", enabled=True)
    fast_mode.set_mode("BP_Privat", enabled=True)

    result = fast_mode.set_mode("BW_Work", enabled=False)

    assert result == {"account": "BW_Work", "state": "flex"}
    assert fast_mode.active_mode("BW_Work") is None
    assert fast_mode.active_mode("BP_Privat") == {
        "account": "BP_Privat",
        "state": "fast",
        "reason": "unspecified",
        "until_utc": None,
    }


@pytest.mark.parametrize("account", ("", "../escape", "a/b", "with space", "x" * 65, None))
def test_invalid_accounts_are_rejected_before_state_access(
    configured_fast_mode: dict[str, object], account: object
) -> None:
    with pytest.raises(fast_mode.FastModeError, match="invalid_fast_mode_account"):
        fast_mode.set_mode(account, enabled=True)  # type: ignore[arg-type]

    assert fast_mode.snapshot() == {"schema_version": 1, "modes": {}}


@pytest.mark.parametrize("until_utc", ("not-a-time", "2026-08-23 13:00:00Z", "2026-08-23T13:00:00", 17))
def test_invalid_expiry_is_rejected(configured_fast_mode: dict[str, object], until_utc: object) -> None:
    with pytest.raises(fast_mode.FastModeError, match="invalid_fast_mode_expiry"):
        fast_mode.set_mode("BW_Work", enabled=True, until_utc=until_utc)  # type: ignore[arg-type]


def test_expiry_boundary_disables_only_expired_account(configured_fast_mode: dict[str, object]) -> None:
    fast_mode.set_mode("BW_Work", enabled=True, until_utc="2026-08-23T12:15:00Z")
    fast_mode.set_mode("BP_Privat", enabled=True)
    clock = configured_fast_mode["clock"]
    assert isinstance(clock, dict)
    clock["now"] = NOW + timedelta(minutes=15)

    assert fast_mode.active_mode("BW_Work") is None
    assert fast_mode.active_mode("BP_Privat") is not None
    assert set(fast_mode.snapshot()["modes"]) == {"BP_Privat"}


def test_valid_exhaustion_disables_only_affected_account(configured_fast_mode: dict[str, object]) -> None:
    fast_mode.set_mode("BW_Work", enabled=True)
    fast_mode.set_mode("BP_Privat", enabled=True)
    snapshots = configured_fast_mode["snapshots"]
    assert isinstance(snapshots, dict)
    snapshots["BW_Work"] = exhausted_snapshot("BW_Work")

    assert fast_mode.active_mode("BW_Work") is None
    assert fast_mode.active_mode("BP_Privat") is not None


@pytest.mark.parametrize(
    "snapshot",
    (
        None,
        {"schema_version": 2, "account": "BW_Work", "exhausted": True},
        {"schema_version": 1, "account": "other", "exhausted": True},
        {"schema_version": 1, "account": "BW_Work", "exhausted": "yes"},
        {"schema_version": 1, "account": "BW_Work", "exhausted": True, "padding": "x" * 16_385},
    ),
)
def test_missing_invalid_or_oversize_snapshot_never_forges_exhaustion(
    configured_fast_mode: dict[str, object], snapshot: object
) -> None:
    fast_mode.set_mode("BW_Work", enabled=True)
    snapshots = configured_fast_mode["snapshots"]
    assert isinstance(snapshots, dict)
    snapshots["BW_Work"] = snapshot

    assert fast_mode.active_mode("BW_Work") is not None


def test_reminder_waits_fifteen_minutes_and_notification_failure_keeps_mode(
    configured_fast_mode: dict[str, object], monkeypatch: pytest.MonkeyPatch
) -> None:
    fast_mode.set_mode("BW_Work", enabled=True)
    notifications = configured_fast_mode["notifications"]
    assert isinstance(notifications, list)
    notifications.clear()

    assert fast_mode.maybe_notify_fast("BW_Work", now=NOW + timedelta(minutes=14, seconds=59)) is False
    assert fast_mode.maybe_notify_fast("BW_Work", now=NOW + timedelta(minutes=15)) is True
    assert len(notifications) == 1

    def fail(_payload: object) -> None:
        raise OSError("desktop unavailable")

    monkeypatch.setattr(fast_mode, "_notifier", fail)
    assert fast_mode.maybe_notify_fast("BW_Work", now=NOW + timedelta(minutes=30)) is False
    assert fast_mode.active_mode("BW_Work") is not None


def test_corrupt_or_oversize_state_fails_safe_without_overwrite(
    configured_fast_mode: dict[str, object], monkeypatch: pytest.MonkeyPatch
) -> None:
    state_path = configured_fast_mode["state_path"]
    assert isinstance(state_path, Path)
    state_path.parent.mkdir(mode=0o700)
    state_path.write_text("{not-json", encoding="utf-8")
    state_path.chmod(0o600)

    assert fast_mode.active_mode("BW_Work") is None
    assert fast_mode.snapshot() == {"schema_version": 1, "modes": {}}
    with pytest.raises(fast_mode.FastModeError, match="fast_mode_state_invalid"):
        fast_mode.set_mode("BW_Work", enabled=True)
    assert state_path.read_text(encoding="utf-8") == "{not-json"

    state_path.write_text(json.dumps({"schema_version": 1, "modes": {"BW_Work": {"padding": "x" * 16_385}}}), encoding="utf-8")
    state_path.chmod(0o600)
    assert fast_mode.active_mode("BW_Work") is None

    state_path.unlink()
    monkeypatch.setattr(
        fast_mode,
        "_write_state_to_parent",
        lambda _parent_fd, _state: (_ for _ in ()).throw(fast_mode.FastModeError("fast_mode_state_write_failed")),
    )
    with pytest.raises(fast_mode.FastModeError, match="fast_mode_state_write_failed"):
        fast_mode.set_mode("BW_Work", enabled=True)
    assert fast_mode.active_mode("BW_Work") is None


def test_state_path_rejects_intermediate_symlink_and_parent_swap(
    configured_fast_mode: dict[str, object], monkeypatch: pytest.MonkeyPatch
) -> None:
    state_root = configured_fast_mode["state_root"]
    assert isinstance(state_root, Path)
    redirected = state_root / "redirected"
    redirected.mkdir(mode=0o700)
    (state_root / "linked").symlink_to(redirected, target_is_directory=True)
    monkeypatch.setattr(fast_mode, "_STATE_PATH", state_root / "linked" / "state" / "fast-mode.json")

    with pytest.raises(fast_mode.FastModeError):
        fast_mode.set_mode("BW_Work", enabled=True)
    assert not (redirected / "state" / "fast-mode.json").exists()

    state_parent = state_root / "race-parent"
    replacement = state_root / "replacement-parent"
    state_parent.mkdir(mode=0o700)
    replacement.mkdir(mode=0o700)
    monkeypatch.setattr(fast_mode, "_STATE_PATH", state_parent / "fast-mode.json")
    real_open = fast_mode.os.open
    swapped = False

    def swap_before_parent_open(path: object, flags: int, *args: object, **kwargs: object) -> int:
        nonlocal swapped
        is_parent = path == state_parent or (path == state_parent.name and kwargs.get("dir_fd") is not None)
        if not swapped and is_parent:
            state_parent.rename(state_root / "original-parent")
            replacement.rename(state_parent)
            swapped = True
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(fast_mode.os, "open", swap_before_parent_open)
    with pytest.raises(fast_mode.FastModeError):
        fast_mode.set_mode("BW_Work", enabled=True)
    assert swapped
    assert not (state_parent / "fast-mode.json").exists()


def test_state_rejects_final_symlink_hardlink_bad_mode_and_non_regular_file(
    configured_fast_mode: dict[str, object], monkeypatch: pytest.MonkeyPatch
) -> None:
    state_root = configured_fast_mode["state_root"]
    assert isinstance(state_root, Path)
    parent = state_root / "state-parent"
    parent.mkdir(mode=0o700)
    state_path = parent / "fast-mode.json"
    monkeypatch.setattr(fast_mode, "_STATE_PATH", state_path)
    backing = state_root / "backing.json"
    backing.write_text("{}", encoding="utf-8")
    backing.chmod(0o600)

    state_path.symlink_to(backing)
    with pytest.raises(fast_mode.FastModeError):
        fast_mode.set_mode("BW_Work", enabled=True)
    state_path.unlink()

    os.link(backing, state_path)
    with pytest.raises(fast_mode.FastModeError):
        fast_mode.set_mode("BW_Work", enabled=True)
    state_path.unlink()

    state_path.write_text("{}", encoding="utf-8")
    state_path.chmod(0o644)
    with pytest.raises(fast_mode.FastModeError):
        fast_mode.set_mode("BW_Work", enabled=True)
    state_path.unlink()

    os.mkfifo(state_path, 0o600)
    with pytest.raises(fast_mode.FastModeError):
        fast_mode.set_mode("BW_Work", enabled=True)

    unsafe_parent = state_root / "unsafe-parent"
    unsafe_parent.mkdir(mode=0o700)
    unsafe_parent.chmod(0o755)
    monkeypatch.setattr(fast_mode, "_STATE_PATH", unsafe_parent / "fast-mode.json")
    with pytest.raises(fast_mode.FastModeError):
        fast_mode.set_mode("BW_Work", enabled=True)


def test_concurrent_enables_keep_both_accounts(configured_fast_mode: dict[str, object], monkeypatch: pytest.MonkeyPatch) -> None:
    state_root = configured_fast_mode["state_root"]
    assert isinstance(state_root, Path)
    for attempt in range(12):
        state_path = state_root / f"enable-{attempt}" / "fast-mode.json"
        _run_race(
            monkeypatch,
            state_root,
            state_path,
            (("enable", "BW_Work", NOW), ("enable", "BP_Privat", NOW)),
        )
        assert set(fast_mode.snapshot()["modes"]) == {"BW_Work", "BP_Privat"}


def test_concurrent_enable_disable_keeps_requested_final_accounts(
    configured_fast_mode: dict[str, object], monkeypatch: pytest.MonkeyPatch
) -> None:
    state_root = configured_fast_mode["state_root"]
    assert isinstance(state_root, Path)
    for attempt in range(12):
        state_path = state_root / f"toggle-{attempt}" / "fast-mode.json"
        monkeypatch.setattr(fast_mode, "_STATE_ROOT", state_root, raising=False)
        monkeypatch.setattr(fast_mode, "_STATE_PATH", state_path)
        fast_mode.set_mode("BW_Work", enabled=True)
        _run_race(
            monkeypatch,
            state_root,
            state_path,
            (("disable", "BW_Work", NOW), ("enable", "BP_Privat", NOW)),
        )
        assert fast_mode.active_mode("BW_Work") is None
        assert fast_mode.active_mode("BP_Privat") is not None


def test_concurrent_expiry_reminder_does_not_resurrect_mode(
    configured_fast_mode: dict[str, object], monkeypatch: pytest.MonkeyPatch
) -> None:
    state_root = configured_fast_mode["state_root"]
    assert isinstance(state_root, Path)
    for attempt in range(12):
        state_path = state_root / f"expiry-{attempt}" / "fast-mode.json"
        monkeypatch.setattr(fast_mode, "_STATE_ROOT", state_root, raising=False)
        monkeypatch.setattr(fast_mode, "_STATE_PATH", state_path)
        clock = configured_fast_mode["clock"]
        assert isinstance(clock, dict)
        clock["now"] = NOW - timedelta(hours=1)
        fast_mode.set_mode("BW_Work", enabled=True, until_utc="2026-08-23T12:10:00Z")
        _run_race(
            monkeypatch,
            state_root,
            state_path,
            (
                ("expire", "BW_Work", NOW + timedelta(minutes=11)),
                ("remind", "BW_Work", NOW),
            ),
        )
        clock["now"] = NOW + timedelta(minutes=11)
        assert fast_mode.active_mode("BW_Work") is None


def test_default_usage_adapter_exhausts_only_valid_private_local_snapshot(
    configured_fast_mode: dict[str, object], monkeypatch: pytest.MonkeyPatch
) -> None:
    state_root = configured_fast_mode["state_root"]
    assert isinstance(state_root, Path)
    usage_root = state_root / "codex-usage"
    current = usage_root / "current"
    current.mkdir(parents=True, mode=0o700)
    current.chmod(0o700)
    snapshot_path = current / "BW_Work.json"
    snapshot_path.write_text(
        json.dumps(
            {
                "account": "BW_Work",
                "status": "ok",
                "captured_at": "2026-08-23T12:00:00Z",
                "stale": False,
                "main": {"windows": [{"name": "weekly", "remaining": 0, "percent": 0}]},
            }
        ),
        encoding="utf-8",
    )
    snapshot_path.chmod(0o600)
    monkeypatch.setattr(fast_mode, "_USAGE_ROOT", usage_root, raising=False)
    monkeypatch.setattr(fast_mode, "_USAGE_ROOT_ANCHOR", state_root, raising=False)
    monkeypatch.setattr(fast_mode, "_snapshot_reader", getattr(fast_mode, "_default_usage_snapshot", None))

    fast_mode.set_mode("BW_Work", enabled=True)

    assert fast_mode.active_mode("BW_Work") is None


def test_default_notifier_has_bounded_redacted_desktop_payload(
    configured_fast_mode: dict[str, object], monkeypatch: pytest.MonkeyPatch
) -> None:
    messages: list[tuple[str, str]] = []
    monkeypatch.setattr(fast_mode, "_desktop_notify", lambda title, body: messages.append((title, body)), raising=False)
    monkeypatch.setattr(fast_mode, "_notifier", getattr(fast_mode, "_default_notifier", None))

    fast_mode.set_mode("BW_Work", enabled=True, reason="Bearer private-token-value")

    assert messages == [("Codex Master", "Fast mode active for BW_Work.")]


class _FakeDesktopContext:
    def __init__(self) -> None:
        self.callbacks: list[object] = []
        self.pushes = 0
        self.pops = 0

    def push_thread_default(self) -> None:
        self.pushes += 1

    def pop_thread_default(self) -> None:
        self.pops += 1

    def pending(self) -> bool:
        return bool(self.callbacks)

    def iteration(self, may_block: bool) -> bool:
        assert may_block is False
        callback = self.callbacks.pop(0)
        assert callable(callback)
        callback()
        return True


class _FakeDesktop:
    def __init__(self, outcome: str) -> None:
        self.outcome = outcome
        self.context = _FakeDesktopContext()
        self.sync_calls = 0
        self.setup_calls = 0
        self.notify_calls: list[tuple[object, ...]] = []
        self.cancellables: list[object] = []
        self.setup_callback: object | None = None
        self.setup_user_data: object | None = None
        self.gio = self._gio()
        self.glib = self._glib()

    def _gio(self) -> object:
        desktop = self

        class Cancellable:
            def __init__(self) -> None:
                self.cancelled = False
                desktop.cancellables.append(self)

            def cancel(self) -> None:
                self.cancelled = True

        class Proxy:
            def call(self, *args: object) -> None:
                desktop.notify_calls.append(args)
                callback = args[-2]
                user_data = args[-1]
                assert callable(callback)
                if desktop.outcome == "call_error":
                    desktop.context.callbacks.append(
                        lambda: callback(self, RuntimeError("notify unavailable"), user_data)
                    )
                else:
                    desktop.context.callbacks.append(lambda: callback(self, "notify-ok", user_data))

            def call_sync(self, *args: object) -> None:
                desktop.notify_calls.append(args)

            def call_finish(self, result: object) -> object:
                if isinstance(result, Exception):
                    raise result
                return result

        proxy = Proxy()

        class DBusProxy:
            @staticmethod
            def new_for_bus_sync(*args: object) -> Proxy:
                desktop.sync_calls += 1
                return proxy

            @staticmethod
            def new_for_bus(*args: object) -> None:
                desktop.setup_calls += 1
                desktop.setup_callback = args[-2]
                desktop.setup_user_data = args[-1]
                callback = args[-2]
                user_data = args[-1]
                assert callable(callback)
                if desktop.outcome == "success" or desktop.outcome == "call_error":
                    desktop.context.callbacks.append(lambda: callback(None, "proxy-ok", user_data))
                elif desktop.outcome == "setup_error":
                    desktop.context.callbacks.append(
                        lambda: callback(None, RuntimeError("session bus unavailable"), user_data)
                    )

            @staticmethod
            def new_for_bus_finish(result: object) -> Proxy:
                if isinstance(result, Exception):
                    raise result
                return proxy

        return types.SimpleNamespace(
            BusType=types.SimpleNamespace(SESSION="session"),
            DBusProxyFlags=types.SimpleNamespace(DO_NOT_LOAD_PROPERTIES="no-properties"),
            DBusCallFlags=types.SimpleNamespace(NONE="none"),
            Cancellable=Cancellable,
            DBusProxy=DBusProxy,
        )

    def _glib(self) -> object:
        desktop = self

        class MainContext:
            @staticmethod
            def new() -> _FakeDesktopContext:
                return desktop.context

        return types.SimpleNamespace(MainContext=MainContext, Variant=lambda signature, value: (signature, value))

    def finish_setup_late(self) -> None:
        assert callable(self.setup_callback)
        self.setup_callback(None, "proxy-ok", self.setup_user_data)


def _install_fake_desktop(
    monkeypatch: pytest.MonkeyPatch, outcome: str
) -> tuple[_FakeDesktop, dict[str, float]]:
    desktop = _FakeDesktop(outcome)
    repository = types.ModuleType("gi.repository")
    repository.Gio = desktop.gio
    repository.GLib = desktop.glib
    gi = types.ModuleType("gi")
    gi.repository = repository
    monkeypatch.setitem(sys.modules, "gi", gi)
    monkeypatch.setitem(sys.modules, "gi.repository", repository)
    clock = {"value": 0.0}
    monkeypatch.setattr(fast_mode.time, "monotonic", lambda: clock["value"], raising=False)
    monkeypatch.setattr(
        fast_mode.time,
        "sleep",
        lambda duration: clock.__setitem__("value", clock["value"] + duration),
        raising=False,
    )
    return desktop, clock


def test_default_notifier_bounds_unresponsive_proxy_and_cleans_up(
    configured_fast_mode: dict[str, object], monkeypatch: pytest.MonkeyPatch
) -> None:
    desktop, clock = _install_fake_desktop(monkeypatch, "hang")
    monkeypatch.setattr(fast_mode, "_notifier", fast_mode._default_notifier)

    fast_mode.set_mode("BW_Work", enabled=True)

    assert desktop.sync_calls == 0
    assert desktop.setup_calls == 1
    assert len(desktop.cancellables) == 1
    assert desktop.cancellables[0].cancelled is True
    assert desktop.context.pushes == desktop.context.pops == 1
    assert clock["value"] >= 1.0
    assert fast_mode.active_mode("BW_Work") is not None


def test_default_notifier_cancellation_ignores_late_proxy_callback(
    configured_fast_mode: dict[str, object], monkeypatch: pytest.MonkeyPatch
) -> None:
    desktop, _clock = _install_fake_desktop(monkeypatch, "hang")
    monkeypatch.setattr(fast_mode, "_notifier", fast_mode._default_notifier)

    fast_mode.set_mode("BW_Work", enabled=True)
    desktop.finish_setup_late()

    assert desktop.notify_calls == []
    assert desktop.context.pushes == desktop.context.pops == 1
    assert fast_mode.active_mode("BW_Work") is not None


def test_default_notifier_async_success_uses_single_deadline_bound_call(
    configured_fast_mode: dict[str, object], monkeypatch: pytest.MonkeyPatch
) -> None:
    desktop, clock = _install_fake_desktop(monkeypatch, "success")
    monkeypatch.setattr(fast_mode, "_notifier", fast_mode._default_notifier)

    fast_mode.set_mode("BW_Work", enabled=True)

    assert desktop.sync_calls == 0
    assert len(desktop.notify_calls) == 1
    assert desktop.cancellables[0].cancelled is False
    assert desktop.context.callbacks == []
    assert desktop.context.pushes == desktop.context.pops == 1
    assert clock["value"] == 0.0


@pytest.mark.parametrize("outcome", ("setup_error", "call_error"))
def test_default_notifier_async_errors_cancel_and_preserve_mode(
    configured_fast_mode: dict[str, object], monkeypatch: pytest.MonkeyPatch, outcome: str
) -> None:
    desktop, _clock = _install_fake_desktop(monkeypatch, outcome)
    monkeypatch.setattr(fast_mode, "_notifier", fast_mode._default_notifier)

    fast_mode.set_mode("BW_Work", enabled=True)

    assert desktop.sync_calls == 0
    assert desktop.cancellables[0].cancelled is True
    assert desktop.context.callbacks == []
    assert desktop.context.pushes == desktop.context.pops == 1
    assert fast_mode.active_mode("BW_Work") is not None


@pytest.mark.parametrize("kind", ("corrupt", "oversize", "symlink"))
def test_default_usage_adapter_rejects_invalid_current_without_legacy_fallback(
    configured_fast_mode: dict[str, object], monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    state_root = configured_fast_mode["state_root"]
    assert isinstance(state_root, Path)
    usage_root = state_root / "codex-usage"
    current = usage_root / "current"
    legacy = usage_root / "snapshots"
    current.mkdir(parents=True, mode=0o700)
    legacy.mkdir(mode=0o700)
    current.chmod(0o700)
    legacy.chmod(0o700)
    current_path = current / "BW_Work.json"
    legacy_path = legacy / "BW_Work.json"
    legacy_path.write_text(
        json.dumps(
            {
                "account": "BW_Work",
                "status": "ok",
                "captured_at": "2026-08-23T12:00:00Z",
                "stale": False,
                "main": {"windows": [{"name": "weekly", "remaining": 0, "percent": 0}]},
            }
        ),
        encoding="utf-8",
    )
    legacy_path.chmod(0o600)
    if kind == "corrupt":
        current_path.write_text("{not-json", encoding="utf-8")
    elif kind == "oversize":
        current_path.write_text("x" * (fast_mode._MAX_SNAPSHOT_BYTES + 1), encoding="utf-8")
    else:
        outside = state_root / "outside-usage.json"
        outside.write_text("{}", encoding="utf-8")
        outside.chmod(0o600)
        current_path.symlink_to(outside)
    if not current_path.is_symlink():
        current_path.chmod(0o600)
    monkeypatch.setattr(fast_mode, "_USAGE_ROOT", usage_root)
    monkeypatch.setattr(fast_mode, "_USAGE_ROOT_ANCHOR", state_root)
    monkeypatch.setattr(fast_mode, "_snapshot_reader", fast_mode._default_usage_snapshot)

    fast_mode.set_mode("BW_Work", enabled=True)

    assert fast_mode.active_mode("BW_Work") is not None


def test_failed_enable_notification_is_attempted_once_and_keeps_mode(
    configured_fast_mode: dict[str, object], monkeypatch: pytest.MonkeyPatch
) -> None:
    attempts: list[object] = []

    def fail(payload: object) -> None:
        attempts.append(payload)
        raise OSError("desktop unavailable")

    monkeypatch.setattr(fast_mode, "_notifier", fail)

    fast_mode.set_mode("BW_Work", enabled=True)

    assert len(attempts) == 1
    assert fast_mode.active_mode("BW_Work") is not None


def test_now_utc_requests_an_aware_utc_timestamp(monkeypatch: pytest.MonkeyPatch) -> None:
    expected = datetime(2026, 8, 29, 10, 30, tzinfo=timezone.utc)
    requested: list[object] = []

    class Clock:
        @classmethod
        def now(cls, zone: object) -> datetime:
            requested.append(zone)
            return expected

    monkeypatch.setattr(fast_mode, "datetime", Clock)

    assert fast_mode._now_utc() == expected
    assert requested == [timezone.utc]


def test_write_state_uses_a_creating_transaction_and_passes_its_parent_fd(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    @contextmanager
    def transaction(*, create: bool):
        captured["create"] = create
        yield 73

    monkeypatch.setattr(fast_mode, "_state_transaction", transaction)
    monkeypatch.setattr(
        fast_mode,
        "_write_state_to_parent",
        lambda parent_fd, state: captured.update(parent_fd=parent_fd, state=state),
    )
    state = {"schema_version": 1, "modes": {}}

    fast_mode._write_state(state)

    assert captured == {"create": True, "parent_fd": 73, "state": state}
