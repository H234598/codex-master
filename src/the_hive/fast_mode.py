"""Account-scoped Fast-mode state with private transactional persistence."""

from __future__ import annotations

import fcntl
import json
import math
import os
import re
import secrets
import stat
import threading
import time
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path


_ACCOUNT_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
_RFC3339_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})$"
)
_MAX_STATE_BYTES = 16 * 1024
_MAX_SNAPSHOT_BYTES = 64 * 1024
_MAX_REASON_CHARS = 500
_MAX_USAGE_WINDOWS = 32
_REMINDER_INTERVAL = timedelta(minutes=15)
_USAGE_MAX_AGE = timedelta(minutes=15)
_LOCK_ATTEMPTS = 50
_LOCK_DELAY_SECONDS = 0.02
_DESKTOP_NOTIFY_TIMEOUT_SECONDS = 1.0
_DESKTOP_NOTIFY_POLL_SECONDS = 0.005
_DESKTOP_NOTIFY_DRAIN_LIMIT = 32
_STATE_ROOT = Path("/")
_STATE_PATH = Path.home() / ".local" / "state" / "codex-master-mcp" / "fast-mode.json"
_USAGE_ROOT: Path | None = None
_USAGE_ROOT_ANCHOR = Path("/")
_THREAD_LOCK = threading.Lock()

SnapshotReader = Callable[[str], Mapping[str, object] | None]
Notifier = Callable[[Mapping[str, object]], None]


class FastModeError(ValueError):
    """Raised for invalid Fast-mode requests or durable state failures."""


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _error(code: str) -> None:
    raise FastModeError(code)


def _validate_account(account: object) -> str:
    if not isinstance(account, str) or not _ACCOUNT_RE.fullmatch(account):
        _error("invalid_fast_mode_account")
    return account


def _validate_now(value: object) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        _error("invalid_fast_mode_time")
    return value.astimezone(timezone.utc)


def _parse_rfc3339(value: object) -> tuple[datetime, str]:
    if not isinstance(value, str) or len(value) > 64 or not _RFC3339_RE.fullmatch(value):
        _error("invalid_fast_mode_expiry")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        _error("invalid_fast_mode_expiry")
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        _error("invalid_fast_mode_expiry")
    parsed = parsed.astimezone(timezone.utc)
    return parsed, parsed.isoformat().replace("+00:00", "Z")


def _reason_code(reason: object) -> str:
    if not isinstance(reason, str) or len(reason) > _MAX_REASON_CHARS:
        _error("invalid_fast_mode_reason")
    return "unspecified" if not reason else "operator_request"


def _state_template() -> dict[str, object]:
    return {"schema_version": 1, "modes": {}}


def _validate_mode(account: object, value: object) -> dict[str, object]:
    _validate_account(account)
    if not isinstance(value, Mapping) or set(value) != {"reason", "until_utc", "last_notified_at_utc"}:
        _error("fast_mode_state_invalid")
    reason = value["reason"]
    until_utc = value["until_utc"]
    last_notified = value["last_notified_at_utc"]
    if not isinstance(reason, str) or reason not in {"unspecified", "operator_request"}:
        _error("fast_mode_state_invalid")
    if until_utc is not None:
        _parse_rfc3339(until_utc)
    if last_notified is not None:
        _parse_rfc3339(last_notified)
    return {"reason": reason, "until_utc": until_utc, "last_notified_at_utc": last_notified}


def _validate_state(value: object) -> dict[str, object]:
    if (
        not isinstance(value, Mapping)
        or set(value) != {"schema_version", "modes"}
        or type(value["schema_version"]) is not int
        or value["schema_version"] != 1
    ):
        _error("fast_mode_state_invalid")
    modes = value["modes"]
    if not isinstance(modes, Mapping) or len(modes) > 128:
        _error("fast_mode_state_invalid")
    return {"schema_version": 1, "modes": {account: _validate_mode(account, mode) for account, mode in modes.items()}}


def _same_identity(first: os.stat_result, current: os.stat_result) -> bool:
    return (
        first.st_dev,
        first.st_ino,
        first.st_mode,
        first.st_uid,
        first.st_gid,
        first.st_nlink,
        first.st_size,
    ) == (
        current.st_dev,
        current.st_ino,
        current.st_mode,
        current.st_uid,
        current.st_gid,
        current.st_nlink,
        current.st_size,
    )


def _same_directory_identity(first: os.stat_result, current: os.stat_result) -> bool:
    return (first.st_dev, first.st_ino, first.st_mode, first.st_uid, first.st_gid) == (
        current.st_dev,
        current.st_ino,
        current.st_mode,
        current.st_uid,
        current.st_gid,
    )


def _safe_directory(item: os.stat_result, *, private: bool) -> bool:
    mode = stat.S_IMODE(item.st_mode)
    if not stat.S_ISDIR(item.st_mode) or item.st_uid not in {0, os.geteuid()} or mode & 0o022:
        return False
    return not private or (item.st_uid == os.geteuid() and mode == 0o700)


def _safe_state_file(item: os.stat_result) -> bool:
    return (
        stat.S_ISREG(item.st_mode)
        and item.st_uid == os.geteuid()
        and item.st_nlink == 1
        and stat.S_IMODE(item.st_mode) == 0o600
        and item.st_size <= _MAX_STATE_BYTES
    )


def _safe_usage_file(item: os.stat_result) -> bool:
    return (
        stat.S_ISREG(item.st_mode)
        and item.st_uid == os.geteuid()
        and item.st_nlink == 1
        and stat.S_IMODE(item.st_mode) == 0o600
        and item.st_size <= _MAX_SNAPSHOT_BYTES
    )


def _path_parts(path: Path, anchor: Path, *, error: str) -> tuple[str, ...]:
    if not isinstance(path, Path) or not isinstance(anchor, Path) or not path.is_absolute() or not anchor.is_absolute():
        _error(error)
    try:
        relative = path.relative_to(anchor)
    except ValueError:
        _error(error)
    parts = relative.parts
    if any(part in {"", ".", ".."} for part in parts):
        _error(error)
    return parts


def _open_anchor(anchor: Path, *, error: str) -> int:
    try:
        before = anchor.lstat()
        if stat.S_ISLNK(before.st_mode) or not _safe_directory(before, private=False):
            _error(error)
        descriptor = os.open(anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except OSError:
        _error(error)
    opened = os.fstat(descriptor)
    if not _same_directory_identity(before, opened) or not _safe_directory(opened, private=False):
        os.close(descriptor)
        _error(error)
    return descriptor


def _open_directory_chain(
    path: Path,
    *,
    anchor: Path,
    create: bool,
    private_final: bool,
    error: str,
) -> int | None:
    parts = _path_parts(path, anchor, error=error)
    descriptor = _open_anchor(anchor, error=error)
    try:
        for index, part in enumerate(parts):
            private = private_final and index == len(parts) - 1
            try:
                before = os.stat(part, dir_fd=descriptor, follow_symlinks=False)
            except FileNotFoundError:
                if not create:
                    return None
                try:
                    os.mkdir(part, 0o700, dir_fd=descriptor)
                except FileExistsError:
                    pass
                except OSError:
                    _error(error)
                try:
                    before = os.stat(part, dir_fd=descriptor, follow_symlinks=False)
                except OSError:
                    _error(error)
            except OSError:
                _error(error)
            if not _safe_directory(before, private=private):
                _error(error)
            try:
                child = os.open(
                    part,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                    dir_fd=descriptor,
                )
            except OSError:
                _error(error)
            opened = os.fstat(child)
            if not _same_directory_identity(before, opened) or not _safe_directory(opened, private=private):
                os.close(child)
                _error(error)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _open_state_parent(*, create: bool) -> int | None:
    path = _STATE_PATH
    if not isinstance(path, Path) or path.name != "fast-mode.json":
        _error("fast_mode_state_invalid")
    return _open_directory_chain(
        path.parent,
        anchor=_STATE_ROOT,
        create=create,
        private_final=True,
        error="fast_mode_state_invalid",
    )


def _read_state_from_parent(parent_fd: int | None) -> dict[str, object]:
    if parent_fd is None:
        return _state_template()
    try:
        before = os.stat(_STATE_PATH.name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return _state_template()
    except OSError:
        _error("fast_mode_state_invalid")
    if not _safe_state_file(before):
        _error("fast_mode_state_invalid")
    try:
        descriptor = os.open(
            _STATE_PATH.name,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=parent_fd,
        )
    except OSError:
        _error("fast_mode_state_invalid")
    try:
        opened = os.fstat(descriptor)
        if not _same_identity(before, opened) or not _safe_state_file(opened):
            _error("fast_mode_state_invalid")
        raw = os.read(descriptor, _MAX_STATE_BYTES + 1)
    finally:
        os.close(descriptor)
    if len(raw) > _MAX_STATE_BYTES:
        _error("fast_mode_state_invalid")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        _error("fast_mode_state_invalid")
    return _validate_state(payload)


def _open_lock(parent_fd: int) -> int:
    name = ".fast-mode.lock"
    for _ in range(_LOCK_ATTEMPTS):
        try:
            before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            try:
                descriptor = os.open(
                    name,
                    os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                    0o600,
                    dir_fd=parent_fd,
                )
                os.fchmod(descriptor, 0o600)
                if not _safe_state_file(os.fstat(descriptor)):
                    os.close(descriptor)
                    _error("fast_mode_lock_invalid")
                return descriptor
            except FileExistsError:
                continue
            except OSError:
                _error("fast_mode_lock_invalid")
        except OSError:
            _error("fast_mode_lock_invalid")
        if not _safe_state_file(before):
            _error("fast_mode_lock_invalid")
        try:
            descriptor = os.open(name, os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=parent_fd)
        except OSError:
            _error("fast_mode_lock_invalid")
        opened = os.fstat(descriptor)
        if not _same_identity(before, opened) or not _safe_state_file(opened):
            os.close(descriptor)
            _error("fast_mode_lock_invalid")
        return descriptor
    _error("fast_mode_lock_timeout")


@contextmanager
def _state_transaction(*, create: bool) -> Iterator[int | None]:
    if not _THREAD_LOCK.acquire(timeout=_LOCK_ATTEMPTS * _LOCK_DELAY_SECONDS):
        _error("fast_mode_lock_timeout")
    parent_fd: int | None = None
    lock_fd: int | None = None
    locked = False
    try:
        parent_fd = _open_state_parent(create=create)
        if parent_fd is None:
            yield None
            return
        lock_fd = _open_lock(parent_fd)
        for _ in range(_LOCK_ATTEMPTS):
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                locked = True
                break
            except BlockingIOError:
                time.sleep(_LOCK_DELAY_SECONDS)
            except OSError:
                _error("fast_mode_lock_invalid")
        if not locked:
            _error("fast_mode_lock_timeout")
        yield parent_fd
    finally:
        if locked and lock_fd is not None:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
            except OSError:
                pass
        if lock_fd is not None:
            os.close(lock_fd)
        if parent_fd is not None:
            os.close(parent_fd)
        _THREAD_LOCK.release()


def _read_state() -> dict[str, object]:
    with _state_transaction(create=False) as parent_fd:
        return _read_state_from_parent(parent_fd)


def _write_state_to_parent(parent_fd: int, state_value: Mapping[str, object]) -> None:
    state_value = _validate_state(state_value)
    encoded = (json.dumps(state_value, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    if len(encoded) > _MAX_STATE_BYTES:
        _error("fast_mode_state_too_large")
    temporary = f".{_STATE_PATH.name}.{secrets.token_hex(8)}.tmp"
    descriptor: int | None = None
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
            dir_fd=parent_fd,
        )
        written = 0
        while written < len(encoded):
            written += os.write(descriptor, encoded[written:])
        os.fchmod(descriptor, 0o600)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        os.replace(temporary, _STATE_PATH.name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        os.fsync(parent_fd)
    except OSError:
        _error("fast_mode_state_write_failed")
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            os.unlink(temporary, dir_fd=parent_fd)
        except FileNotFoundError:
            pass
        except OSError:
            pass


def _write_state(state_value: Mapping[str, object]) -> None:
    with _state_transaction(create=True) as parent_fd:
        assert parent_fd is not None
        _write_state_to_parent(parent_fd, state_value)


def _usage_root_path() -> Path | None:
    if _USAGE_ROOT is not None:
        root = _USAGE_ROOT
    else:
        value = os.environ.get("CODEX_USAGE_STATE_ROOT") or os.environ.get("XDG_DATA_HOME")
        root = Path(value) / "codex-usage" if value else Path.home() / ".local" / "share" / "codex-usage"
    return root if isinstance(root, Path) and root.is_absolute() else None


def _read_usage_candidate(path: Path) -> tuple[bool, Mapping[str, object] | None]:
    parent_fd = _open_directory_chain(
        path.parent,
        anchor=_USAGE_ROOT_ANCHOR,
        create=False,
        private_final=False,
        error="fast_mode_usage_invalid",
    )
    if parent_fd is None:
        return False, None
    try:
        try:
            before = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            return False, None
        except OSError:
            _error("fast_mode_usage_invalid")
        if not _safe_usage_file(before):
            _error("fast_mode_usage_invalid")
        try:
            descriptor = os.open(path.name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=parent_fd)
        except OSError:
            _error("fast_mode_usage_invalid")
        try:
            opened = os.fstat(descriptor)
            if not _same_identity(before, opened) or not _safe_usage_file(opened):
                _error("fast_mode_usage_invalid")
            raw = os.read(descriptor, _MAX_SNAPSHOT_BYTES + 1)
        finally:
            os.close(descriptor)
    finally:
        os.close(parent_fd)
    if len(raw) > _MAX_SNAPSHOT_BYTES:
        _error("fast_mode_usage_invalid")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        _error("fast_mode_usage_invalid")
    if not isinstance(payload, Mapping):
        _error("fast_mode_usage_invalid")
    return True, payload


def _finite_nonnegative(value: object) -> float:
    if type(value) not in {int, float} or not math.isfinite(float(value)) or float(value) < 0:
        _error("fast_mode_usage_invalid")
    return float(value)


def _usage_exhausted(payload: Mapping[str, object], account: str, *, now: datetime) -> bool:
    if payload.get("account") != account or payload.get("status") not in {"ok", "blocked"} or payload.get("stale", False) is not False:
        _error("fast_mode_usage_invalid")
    captured_at = payload.get("values_captured_at") or payload.get("captured_at")
    captured, _canonical = _parse_rfc3339(captured_at)
    if captured > now + timedelta(minutes=1) or now - captured > _USAGE_MAX_AGE:
        _error("fast_mode_usage_invalid")
    if payload["status"] == "blocked":
        blocked_until, _canonical = _parse_rfc3339(payload.get("blocked_until"))
        if blocked_until <= now:
            _error("fast_mode_usage_invalid")
        return True
    main = payload.get("main")
    if not isinstance(main, Mapping):
        _error("fast_mode_usage_invalid")
    exhausted = False
    for key in ("exhausted", "limit_reached"):
        flag = main.get(key, False)
        if flag is not None and type(flag) is not bool:
            _error("fast_mode_usage_invalid")
        exhausted = exhausted or flag is True
    windows = main.get("windows", ())
    if not isinstance(windows, list) or len(windows) > _MAX_USAGE_WINDOWS:
        _error("fast_mode_usage_invalid")
    for window in windows:
        if not isinstance(window, Mapping):
            _error("fast_mode_usage_invalid")
        name = window.get("name")
        if not isinstance(name, str) or not 1 <= len(name) <= 64:
            _error("fast_mode_usage_invalid")
        window_exhausted = window.get("exhausted", False)
        if window_exhausted is not None and type(window_exhausted) is not bool:
            _error("fast_mode_usage_invalid")
        remaining = window.get("remaining")
        percent = window.get("percent")
        if remaining is None and percent is None and window_exhausted is not True:
            _error("fast_mode_usage_invalid")
        if remaining is not None:
            exhausted = exhausted or _finite_nonnegative(remaining) == 0
        if percent is not None:
            exhausted = exhausted or _finite_nonnegative(percent) == 0
        exhausted = exhausted or window_exhausted is True
    return exhausted


def _default_usage_snapshot(account: str) -> Mapping[str, object] | None:
    try:
        account = _validate_account(account)
        root = _usage_root_path()
        if root is None:
            return None
        for directory in ("current", "snapshots"):
            found, payload = _read_usage_candidate(root / directory / f"{account}.json")
            if not found:
                continue
            assert payload is not None
            exhausted = _usage_exhausted(payload, account, now=_validate_now(_now_utc()))
            return {"schema_version": 1, "account": account, "exhausted": exhausted}
    except FastModeError:
        return None
    return None


def _gio_modules() -> tuple[object, object]:
    from gi.repository import Gio, GLib

    return Gio, GLib


def _drain_desktop_context(context: object) -> None:
    for _ in range(_DESKTOP_NOTIFY_DRAIN_LIMIT):
        if not context.pending():
            return
        context.iteration(False)


def _desktop_notify(title: str, body: str) -> None:
    Gio, GLib = _gio_modules()
    context = GLib.MainContext.new()
    cancellable = Gio.Cancellable()
    state: dict[str, object] = {
        "closed": False,
        "done": False,
        "error": None,
        "proxy": None,
        "cancellable": cancellable,
    }
    deadline = time.monotonic() + _DESKTOP_NOTIFY_TIMEOUT_SECONDS

    def finish(error: Exception | None = None) -> None:
        if state["closed"] or state["done"]:
            return
        state["error"] = error
        state["done"] = True

    def remaining_timeout_msec() -> int | None:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            finish(TimeoutError("fast_mode_notification_timeout"))
            return None
        return max(1, math.ceil(remaining * 1000))

    def notify_ready(proxy: object, result: object, _user_data: object) -> None:
        if state["closed"] or state["done"]:
            return
        try:
            proxy.call_finish(result)
        except Exception as exc:
            finish(exc)
        else:
            finish()

    def proxy_ready(_source: object, result: object, _user_data: object) -> None:
        if state["closed"] or state["done"]:
            return
        try:
            proxy = Gio.DBusProxy.new_for_bus_finish(result)
        except Exception as exc:
            finish(exc)
            return
        timeout_msec = remaining_timeout_msec()
        if timeout_msec is None or state["closed"] or state["done"]:
            return
        operation_cancellable = state["cancellable"]
        if operation_cancellable is None:
            return
        state["proxy"] = proxy
        try:
            proxy.call(
                "Notify",
                GLib.Variant("(susssasa{sv}i)", ("Codex Master", 0, "dialog-warning", title, body, [], {}, 5000)),
                Gio.DBusCallFlags.NONE,
                timeout_msec,
                operation_cancellable,
                notify_ready,
                None,
            )
        except Exception as exc:
            finish(exc)

    context_pushed = False
    try:
        context.push_thread_default()
        context_pushed = True
        Gio.DBusProxy.new_for_bus(
            Gio.BusType.SESSION,
            Gio.DBusProxyFlags.DO_NOT_LOAD_PROPERTIES,
            None,
            "org.freedesktop.Notifications",
            "/org/freedesktop/Notifications",
            "org.freedesktop.Notifications",
            cancellable,
            proxy_ready,
            None,
        )
        while not state["done"]:
            _drain_desktop_context(context)
            if state["done"]:
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                finish(TimeoutError("fast_mode_notification_timeout"))
                break
            time.sleep(min(_DESKTOP_NOTIFY_POLL_SECONDS, remaining))
        failure = state["error"]
        if isinstance(failure, Exception):
            raise failure
    finally:
        state["closed"] = True
        state["proxy"] = None
        if not state["done"] or state["error"] is not None:
            cancellable.cancel()
        state["cancellable"] = None
        state["error"] = None
        if context_pushed:
            context.pop_thread_default()


def _default_notifier(payload: Mapping[str, object]) -> None:
    if set(payload) != {"account", "state", "reason"}:
        _error("fast_mode_notification_invalid")
    account = _validate_account(payload["account"])
    state = payload["state"]
    reason = payload["reason"]
    if state not in {"fast", "flex"} or reason not in {"unspecified", "operator_request", "disabled", "expired", "limit_exhausted"}:
        _error("fast_mode_notification_invalid")
    body = f"Fast mode {'active' if state == 'fast' else 'inactive'} for {account}."
    _desktop_notify("Codex Master", body)


_snapshot_reader: SnapshotReader | None = _default_usage_snapshot
_notifier: Notifier | None = _default_notifier


def _valid_exhaustion(account: str) -> bool:
    reader = _snapshot_reader
    if reader is None:
        return False
    try:
        source = reader(account)
        if not isinstance(source, Mapping):
            return False
        encoded = json.dumps(source, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")
    except (OverflowError, TypeError, ValueError, OSError):
        return False
    return (
        len(encoded) <= _MAX_SNAPSHOT_BYTES
        and set(source) == {"schema_version", "account", "exhausted"}
        and type(source["schema_version"]) is int
        and source["schema_version"] == 1
        and source["account"] == account
        and type(source["exhausted"]) is bool
        and source["exhausted"] is True
    )


def _mode_view(account: str, mode: Mapping[str, object]) -> dict[str, object]:
    return {"account": account, "state": "fast", "reason": mode["reason"], "until_utc": mode["until_utc"]}


def _notify(payload: Mapping[str, object]) -> bool:
    notifier = _notifier
    if notifier is None:
        return False
    try:
        notifier(dict(payload))
    except Exception:
        return False
    return True


def _remove_mode(parent_fd: int, state_value: Mapping[str, object], account: str) -> None:
    modes = dict(state_value["modes"])
    modes.pop(account, None)
    _write_state_to_parent(parent_fd, {"schema_version": 1, "modes": modes})


def _active_mode_in_transaction(
    account: str,
    *,
    now: datetime,
    parent_fd: int | None,
) -> tuple[Mapping[str, object] | None, Mapping[str, object] | None]:
    state_value = _read_state_from_parent(parent_fd)
    modes = state_value["modes"]
    assert isinstance(modes, Mapping)
    raw_mode = modes.get(account)
    if raw_mode is None:
        return None, None
    mode = _validate_mode(account, raw_mode)
    until_utc = mode["until_utc"]
    if until_utc is not None and _parse_rfc3339(until_utc)[0] <= now:
        assert parent_fd is not None
        _remove_mode(parent_fd, state_value, account)
        return None, {"account": account, "state": "flex", "reason": "expired"}
    if _valid_exhaustion(account):
        assert parent_fd is not None
        _remove_mode(parent_fd, state_value, account)
        return None, {"account": account, "state": "flex", "reason": "limit_exhausted"}
    return _mode_view(account, mode), None


def _record_notification(account: str, *, now: datetime) -> Mapping[str, object] | None:
    with _state_transaction(create=False) as parent_fd:
        if parent_fd is None:
            return None
        state_value = _read_state_from_parent(parent_fd)
        active, transition = _active_mode_in_transaction(account, now=now, parent_fd=parent_fd)
        if active is None:
            return transition
        modes = dict(state_value["modes"])
        modes[account] = {**modes[account], "last_notified_at_utc": now.isoformat().replace("+00:00", "Z")}
        _write_state_to_parent(parent_fd, {"schema_version": 1, "modes": modes})
        return None


def active_mode(account: str) -> Mapping[str, object] | None:
    """Return one active account mode, otherwise the caller must use Flex."""

    account = _validate_account(account)
    transition: Mapping[str, object] | None = None
    try:
        with _state_transaction(create=False) as parent_fd:
            if parent_fd is None:
                return None
            result, transition = _active_mode_in_transaction(account, now=_validate_now(_now_utc()), parent_fd=parent_fd)
    except FastModeError:
        return None
    if transition is not None:
        _notify(transition)
    return result


def set_mode(
    account: str,
    *,
    enabled: bool,
    reason: str = "",
    until_utc: str | None = None,
) -> Mapping[str, object]:
    """Persist one account's requested Fast/Flex state and notify on change."""

    account = _validate_account(account)
    if type(enabled) is not bool:
        _error("invalid_fast_mode_enabled")
    reason_code = _reason_code(reason)
    now = _validate_now(_now_utc())
    expiry: str | None = None
    if until_utc is not None:
        parsed, expiry = _parse_rfc3339(until_utc)
        if parsed <= now:
            _error("invalid_fast_mode_expiry")
    transition: Mapping[str, object] | None = None
    with _state_transaction(create=True) as parent_fd:
        assert parent_fd is not None
        state_value = _read_state_from_parent(parent_fd)
        modes = dict(state_value["modes"])
        previous = modes.get(account)
        if enabled:
            previous_mode = _validate_mode(account, previous) if previous is not None else None
            modes[account] = {
                "reason": reason_code,
                "until_utc": expiry,
                "last_notified_at_utc": None if previous_mode is None else previous_mode["last_notified_at_utc"],
            }
            _write_state_to_parent(parent_fd, {"schema_version": 1, "modes": modes})
            result = _mode_view(account, modes[account])
            if previous_mode is None:
                transition = {"account": account, "state": "fast", "reason": reason_code}
        else:
            modes.pop(account, None)
            _write_state_to_parent(parent_fd, {"schema_version": 1, "modes": modes})
            result = {"account": account, "state": "flex"}
            if previous is not None:
                transition = {"account": account, "state": "flex", "reason": "disabled"}
    if transition is not None:
        notified = _notify(transition)
        if enabled and notified:
            try:
                expired = _record_notification(account, now=now)
            except FastModeError:
                expired = None
            if expired is not None:
                _notify(expired)
    return result


def maybe_notify_fast(account: str, *, now: datetime | None = None) -> bool:
    """Emit at most one active-mode reminder per account every fifteen minutes."""

    account = _validate_account(account)
    checked_now = _validate_now(_now_utc() if now is None else now)
    transition: Mapping[str, object] | None = None
    try:
        with _state_transaction(create=False) as parent_fd:
            if parent_fd is None:
                return False
            active, transition = _active_mode_in_transaction(account, now=checked_now, parent_fd=parent_fd)
            if active is None:
                return False
            state_value = _read_state_from_parent(parent_fd)
            modes = state_value["modes"]
            assert isinstance(modes, Mapping)
            stored = _validate_mode(account, modes[account])
            last = stored["last_notified_at_utc"]
            if last is not None and checked_now - _parse_rfc3339(last)[0] < _REMINDER_INTERVAL:
                return False
            reminder = {"account": account, "state": "fast", "reason": stored["reason"]}
    except FastModeError:
        return False
    if transition is not None:
        _notify(transition)
        return False
    if not _notify(reminder):
        return False
    try:
        transition = _record_notification(account, now=checked_now)
    except FastModeError:
        return False
    if transition is not None:
        _notify(transition)
        return False
    return True


def snapshot() -> Mapping[str, object]:
    """Return redacted active Fast-mode state for all known accounts."""

    try:
        state_value = _read_state()
    except FastModeError:
        return _state_template()
    modes = state_value["modes"]
    assert isinstance(modes, Mapping)
    active: dict[str, object] = {}
    for account in tuple(modes):
        mode = active_mode(account)
        if mode is not None:
            active[account] = mode
    return {"schema_version": 1, "modes": active}
