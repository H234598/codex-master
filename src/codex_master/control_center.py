"""GTK control center for codex-master.

Business state stays independent from GTK so contract and concurrency behavior
remain headless-testable.
"""

from __future__ import annotations

import contextlib
import json
import os
import re
import secrets
import selectors
import signal
import subprocess
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Callable

from codex_master.control_catalog import (
    CatalogError,
    FieldDescriptor,
    FieldKind,
    Risk,
    ToolDescriptor,
    compile_catalog,
    effective_risk,
    serialize_arguments,
)
from codex_master.server import (
    AgentError,
    assert_install_context_allows_master_registration,
    public_error_payload,
    require_teamleader_tool_access,
    teamleader_tool_catalog,
)
from codex_master.fleet_control import (
    FleetControlError,
    OllamaPageState,
    ollama_instance_plan_args,
    parse_ollama_page,
)


APPLICATION_ID = "de.teladi.CodexMaster.ControlCenter"
PAGE_SIZE = 20
MAX_FILTER_CHARS = 64
MAX_PAGE_ROWS = 20
MAX_RESULT_DEPTH = 6
MAX_RESULT_ITEMS = 200
MAX_RESULT_CHARS = 16_000
MAX_RESULT_STRING_CHARS = 400
MAX_BACKEND_STDOUT_BYTES = 1024 * 1024
MAX_BACKEND_STDERR_BYTES = 64 * 1024
DEFAULT_BACKEND_TIMEOUT_SECONDS = 180
MAX_BACKEND_TIMEOUT_SECONDS = 660
AGENT_ID_RE = re.compile(r"^[abcu](?:[1-9]|[1-9][0-9]|100)$")
SERIES_FILTER_RE = re.compile(r"^[abcu]$")
STATUS_PAGE_FIELDS = {
    "results",
    "result_count",
    "total_count",
    "agents_offset",
    "agents_limit",
    "truncated",
    "raw_output",
}
PRIVATE_RESULT_KEYS = frozenset(
    {
        "access_token",
        "api_key",
        "authorization",
        "backend_account_id",
        "context",
        "cwd",
        "home",
        "password",
        "prompt",
        "raw_log",
        "response_output",
        "runner",
        "secret",
        "session",
        "task",
        "text",
        "token",
    }
)
LONG_TEXT_FIELDS = frozenset({"context", "forbidden", "prompt", "task", "text"})
TOOL_CATEGORIES = (
    "Alle",
    "Aufträge",
    "Serien",
    "Auth & Limits",
    "Agentinnen",
    "Diagnose",
)


def tool_category(name: str) -> str:
    if name.startswith("agent_assign") or name in {
        "agent_claim",
        "agent_interrupt",
        "agent_last_assignment_status",
        "agent_release",
        "agent_report_request",
        "agent_scope_check",
        "agent_send",
    }:
        return "Aufträge"
    if name in {
        "agent_selector_policy",
        "agent_selector_preview",
        "agent_spawn_offers",
        "agent_start",
        "agent_stop",
        "fleet_watchdog",
    }:
        return "Serien"
    if name in {"agent_routing_decision", "usage_watchdog", "agent_pool_copy_auth"}:
        return "Auth & Limits"
    if name.startswith("agent_pool_"):
        return "Agentinnen"
    return "Diagnose"


@dataclass(frozen=True, slots=True)
class AgentRow:
    agent: str
    activity_state: str
    auth_state: str
    lease_state: str
    limit_state: str
    blocked_until_utc: str | None
    identity_state: str
    role: str
    last_assignment_at_utc: str | None
    can_start: bool
    can_stop: bool
    issue: str | None


@dataclass(frozen=True, slots=True)
class StatusPage:
    rows: tuple[AgentRow, ...]
    result_count: int
    total_count: int
    agents_offset: int
    agents_limit: int
    truncated: bool

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "rows": [asdict(row) for row in self.rows],
            "result_count": self.result_count,
            "total_count": self.total_count,
            "agents_offset": self.agents_offset,
            "agents_limit": self.agents_limit,
            "truncated": self.truncated,
        }


def _non_negative_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _bounded_optional_text(value: Any, *, max_chars: int = 64) -> str | None:
    return value if isinstance(value, str) and 0 < len(value) <= max_chars else None


def _normalize_agent_row(value: Any) -> AgentRow:
    if not isinstance(value, dict):
        raise AgentError("control-center status page is invalid")
    agent = value.get("agent")
    if not isinstance(agent, str) or not AGENT_ID_RE.fullmatch(agent):
        raise AgentError("control-center status page is invalid")
    if "error" in value:
        return AgentRow(
            agent=agent,
            activity_state="unknown",
            auth_state="unknown",
            lease_state="unreadable",
            limit_state="unknown",
            blocked_until_utc=None,
            identity_state="unknown",
            role="unknown",
            last_assignment_at_utc=None,
            can_start=False,
            can_stop=False,
            issue="status_unavailable",
        )

    running = value.get("running")
    if not isinstance(running, bool):
        raise AgentError("control-center status page is invalid")
    auth = value.get("auth")
    lease = value.get("lease")
    identity = value.get("identity_guard")
    usage = value.get("usage_watchdog")
    assignment = value.get("last_assignment")
    if not all(isinstance(item, dict) for item in (auth, lease, identity, usage)):
        raise AgentError("control-center status page is invalid")
    if assignment is None:
        assignment = {}
    if not isinstance(assignment, dict):
        raise AgentError("control-center status page is invalid")

    if auth.get("authenticated") is True:
        auth_state = "ready"
    elif auth.get("auth_state") == "unreadable":
        auth_state = "unknown"
    else:
        auth_state = "blocked"
    raw_lease_state = lease.get("state")
    lease_state = raw_lease_state if raw_lease_state in {"unclaimed", "held", "expired", "unreadable"} else "unreadable"
    identity_state = "verified" if identity.get("ok") is True else "blocked"
    if usage.get("blocked") is True:
        limit_state = "blocked"
    elif usage.get("blocked") is False and usage.get("state") in {"clear", "ok", "released"}:
        limit_state = "clear"
    else:
        limit_state = "unknown"
    blocked_until = _bounded_optional_text(usage.get("blocked_until_utc"), max_chars=40)
    role = assignment.get("role")
    if role not in {"exploriererin", "arbeitsbiene"}:
        role = "unknown"
    last_assignment_at = _bounded_optional_text(assignment.get("created_at_utc"), max_chars=40)
    lease_free = lease_state in {"unclaimed", "expired"}
    can_start = not running and auth_state == "ready" and identity_state == "verified" and lease_free and limit_state == "clear"
    can_stop = running and identity_state == "verified" and lease_free
    return AgentRow(
        agent=agent,
        activity_state="running" if running else "sleeping",
        auth_state=auth_state,
        lease_state=lease_state,
        limit_state=limit_state,
        blocked_until_utc=blocked_until,
        identity_state=identity_state,
        role=role,
        last_assignment_at_utc=last_assignment_at,
        can_start=can_start,
        can_stop=can_stop,
        issue=None,
    )


def normalize_status_page(payload: Any) -> StatusPage:
    if not isinstance(payload, dict) or set(payload) != STATUS_PAGE_FIELDS:
        raise AgentError("control-center status page is invalid")
    results = payload.get("results")
    if not isinstance(results, list) or len(results) > MAX_PAGE_ROWS:
        raise AgentError("control-center status page is invalid")
    result_count = payload.get("result_count")
    total_count = payload.get("total_count")
    offset = payload.get("agents_offset")
    limit = payload.get("agents_limit")
    truncated = payload.get("truncated")
    if (
        not all(_non_negative_int(item) for item in (result_count, total_count, offset, limit))
        or not isinstance(truncated, bool)
        or payload.get("raw_output") != "not_returned"
        or result_count != len(results)
        or result_count > limit
        or limit != PAGE_SIZE
        or offset + result_count > total_count
        or truncated != (offset + result_count < total_count)
    ):
        raise AgentError("control-center status page is invalid")
    rows = tuple(_normalize_agent_row(item) for item in results)
    if len({row.agent for row in rows}) != len(rows):
        raise AgentError("control-center status page is invalid")
    return StatusPage(
        rows=rows,
        result_count=result_count,
        total_count=total_count,
        agents_offset=offset,
        agents_limit=limit,
        truncated=truncated,
    )


def status_query(filter_text: Any, page: Any) -> dict[str, Any]:
    if isinstance(page, bool) or not isinstance(page, int) or page < 0:
        raise AgentError("control-center page is invalid")
    if not isinstance(filter_text, str) or len(filter_text) > MAX_FILTER_CHARS:
        raise AgentError("control-center filter is invalid")
    normalized = filter_text.strip().lower()
    if not normalized:
        selector = "all"
    elif SERIES_FILTER_RE.fullmatch(normalized):
        selector = f"{normalized}-series"
    elif AGENT_ID_RE.fullmatch(normalized):
        selector = normalized
        page = 0
    else:
        raise AgentError("control-center filter is invalid")
    return {
        "agent": selector,
        "agents_offset": page * PAGE_SIZE,
        "agents_limit": PAGE_SIZE,
    }


def bounded_public_result_text(payload: Any) -> str:
    remaining = [MAX_RESULT_ITEMS]

    def clean(value: Any, depth: int) -> Any:
        if remaining[0] <= 0 or depth > MAX_RESULT_DEPTH:
            return "<begrenzt>"
        remaining[0] -= 1
        if value is None or isinstance(value, bool):
            return value
        if isinstance(value, int) and not isinstance(value, bool):
            return value
        if isinstance(value, float):
            return value if value == value and abs(value) != float("inf") else "<ungültige Zahl>"
        if isinstance(value, str):
            return value[:MAX_RESULT_STRING_CHARS]
        if isinstance(value, list):
            return [clean(item, depth + 1) for item in value[:MAX_RESULT_ITEMS]]
        if isinstance(value, dict):
            result: dict[str, Any] = {}
            for key, item in list(value.items())[:MAX_RESULT_ITEMS]:
                if remaining[0] <= 0:
                    break
                if not isinstance(key, str) or not key or len(key) > 80:
                    continue
                normalized = key.lower()
                if normalized in PRIVATE_RESULT_KEYS or normalized.endswith(("_token", "_secret", "_password", "_path")):
                    continue
                result[key] = clean(item, depth + 1)
            return result
        return "<nicht darstellbar>"

    text = json.dumps(clean(payload, 0), ensure_ascii=False, indent=2, sort_keys=True)
    if len(text) > MAX_RESULT_CHARS:
        return text[: MAX_RESULT_CHARS - 13] + "\n<begrenzt>\n"
    return text


def backend_timeout_seconds(tool_name: str, args: dict[str, Any]) -> int:
    if tool_name == "agent_wait":
        requested = args.get("timeout_seconds", 120)
        if isinstance(requested, int) and not isinstance(requested, bool):
            return min(MAX_BACKEND_TIMEOUT_SECONDS, max(30, requested + 30))
    if tool_name in {"agent_pool_copy_auth", "agent_pool_destroy_pool", "agent_pool_install"}:
        return 600
    return DEFAULT_BACKEND_TIMEOUT_SECONDS


class SubprocessToolDispatcher:
    def __init__(
        self,
        *,
        argv: list[str] | None = None,
        timeout_seconds: float | None = None,
    ) -> None:
        self._argv = list(argv) if argv is not None else [str(Path.home() / ".local/bin/codex-master-mcp")]
        self._timeout_seconds = timeout_seconds
        self._instance_id = f"control-center-{secrets.token_hex(16)}"
        self._lock = threading.Lock()
        self._process: subprocess.Popen[bytes] | None = None
        self._cancel_requested = False
        self._state = "idle"

    def prepare(self) -> None:
        with self._lock:
            if self._state != "idle":
                raise AgentError("control-center backend is busy")
            self._state = "pending"
            self._cancel_requested = False

    def abort_prepare(self) -> None:
        with self._lock:
            if self._state == "pending":
                self._state = "idle"
                self._cancel_requested = False

    def _environment(self) -> dict[str, str]:
        allowed = {
            "CODEX_AGENT_MCP_STATE",
            "CODEX_HOME",
            "CODEX_MASTER_MCP_STATE",
            "DISPLAY",
            "HOME",
            "LANG",
            "LC_ALL",
            "LOGNAME",
            "PATH",
            "PYTHONPATH",
            "TMPDIR",
            "USER",
            "WAYLAND_DISPLAY",
            "XDG_RUNTIME_DIR",
        }
        env = {key: value for key, value in os.environ.items() if key in allowed}
        env["CODEX_MASTER_MCP_INSTANCE_ID"] = self._instance_id
        return env

    def __call__(self, tool_name: str, args: dict[str, Any]) -> dict[str, Any]:
        try:
            request = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": tool_name, "arguments": args},
            }
            encoded = (json.dumps(request, ensure_ascii=True, separators=(",", ":")) + "\n").encode("ascii")
            if len(encoded) > MAX_BACKEND_STDOUT_BYTES:
                raise AgentError("control-center backend request exceeded limit")
            timeout = self._timeout_seconds
            if timeout is None:
                timeout = float(backend_timeout_seconds(tool_name, args))
        except BaseException:
            self.abort_prepare()
            raise
        with self._lock:
            if self._state == "idle":
                self._state = "active"
                self._cancel_requested = False
            elif self._state == "pending":
                self._state = "active"
            else:
                raise AgentError("control-center backend is busy")
        process: subprocess.Popen[bytes] | None = None
        cancelled = False
        try:
            process = subprocess.Popen(
                self._argv,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=self._environment(),
                start_new_session=True,
            )
            with self._lock:
                self._process = process
                cancel_before_exchange = self._cancel_requested
            if cancel_before_exchange:
                self._kill_process_group(process)
                raise AgentError("control-center backend outcome unknown after cancellation")
            stdout, stderr = self._bounded_exchange(process, encoded, timeout)
        except subprocess.TimeoutExpired as exc:
            if process is not None:
                self._kill_process_group(process)
                with contextlib.suppress(subprocess.TimeoutExpired):
                    process.wait(timeout=5)
            self._close_process_pipes(process)
            raise AgentError("control-center backend outcome unknown after timeout") from exc
        except AgentError:
            if process is not None and process.poll() is None:
                self._kill_process_group(process)
                with contextlib.suppress(subprocess.TimeoutExpired):
                    process.wait(timeout=5)
            self._close_process_pipes(process)
            raise
        except OSError as exc:
            if process is not None and process.poll() is None:
                self._kill_process_group(process)
                with contextlib.suppress(subprocess.TimeoutExpired):
                    process.wait(timeout=5)
            self._close_process_pipes(process)
            raise AgentError("control-center backend is unavailable") from exc
        except Exception:
            if process is not None and process.poll() is None:
                self._kill_process_group(process)
                with contextlib.suppress(subprocess.TimeoutExpired):
                    process.wait(timeout=5)
            self._close_process_pipes(process)
            raise
        finally:
            with self._lock:
                cancelled = self._cancel_requested
                self._cancel_requested = False
                if self._process is process:
                    self._process = None
                self._state = "idle"
        if process.returncode != 0:
            if cancelled:
                raise AgentError("control-center backend outcome unknown after cancellation")
            raise AgentError("control-center backend failed")
        return self._decode_response(stdout)

    @staticmethod
    def _kill_process_group(process: subprocess.Popen[bytes]) -> None:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except OSError:
            with contextlib.suppress(OSError):
                process.kill()

    @staticmethod
    def _close_process_pipes(process: subprocess.Popen[bytes] | None) -> None:
        if process is None:
            return
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream is not None:
                with contextlib.suppress(OSError):
                    stream.close()

    def cancel(self) -> bool:
        with self._lock:
            if self._state == "idle":
                return False
            process = self._process
            self._cancel_requested = True
        if process is None:
            return True
        if process.poll() is not None:
            return False
        self._kill_process_group(process)
        return True

    @staticmethod
    def _decode_response(raw: bytes) -> dict[str, Any]:
        try:
            response = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
            raise AgentError("control-center backend returned invalid response") from exc
        if not isinstance(response, dict) or response.get("jsonrpc") != "2.0" or response.get("id") != 1:
            raise AgentError("control-center backend returned invalid response")
        result = response.get("result")
        if not isinstance(result, dict) or not isinstance(result.get("isError"), bool):
            raise AgentError("control-center backend returned invalid response")
        content = result.get("content")
        if (
            not isinstance(content, list)
            or len(content) != 1
            or not isinstance(content[0], dict)
            or content[0].get("type") != "text"
            or not isinstance(content[0].get("text"), str)
        ):
            raise AgentError("control-center backend returned invalid response")
        try:
            payload = json.loads(content[0]["text"])
        except (json.JSONDecodeError, RecursionError) as exc:
            raise AgentError("control-center backend returned invalid response") from exc
        if not isinstance(payload, dict):
            raise AgentError("control-center backend returned invalid response")
        if result["isError"] and "error" not in payload:
            return {"error": "control-center backend rejected request"}
        return payload

    @staticmethod
    def _bounded_exchange(
        process: subprocess.Popen[bytes],
        request: bytes,
        timeout_seconds: float,
    ) -> tuple[bytes, bytes]:
        if process.stdin is None or process.stdout is None or process.stderr is None:
            raise AgentError("control-center backend pipes are unavailable")
        stdin_fd = process.stdin.fileno()
        stdout_fd = process.stdout.fileno()
        stderr_fd = process.stderr.fileno()
        streams = {
            stdout_fd: (process.stdout, bytearray(), MAX_BACKEND_STDOUT_BYTES),
            stderr_fd: (process.stderr, bytearray(), MAX_BACKEND_STDERR_BYTES),
        }
        selector = selectors.DefaultSelector()
        deadline = time.monotonic() + timeout_seconds
        pending = memoryview(request)
        try:
            os.set_blocking(stdin_fd, False)
            selector.register(process.stdin, selectors.EVENT_WRITE, data=("input", stdin_fd))
            for fd, (stream, _buffer, _limit) in streams.items():
                os.set_blocking(fd, False)
                selector.register(stream, selectors.EVENT_READ, data=("output", fd))
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(process.args, timeout_seconds)
                events = selector.select(remaining)
                if not events:
                    raise subprocess.TimeoutExpired(process.args, timeout_seconds)
                for key, _mask in events:
                    kind, fd = key.data
                    if kind == "input":
                        try:
                            written = os.write(fd, pending)
                        except BlockingIOError:
                            continue
                        except (BrokenPipeError, OSError) as exc:
                            raise AgentError("control-center backend input failed") from exc
                        pending = pending[written:]
                        if not pending:
                            selector.unregister(process.stdin)
                            process.stdin.close()
                        continue
                    stream, buffer, limit = streams[fd]
                    try:
                        chunk = os.read(fd, min(64 * 1024, limit + 1 - len(buffer)))
                    except BlockingIOError:
                        continue
                    if not chunk:
                        selector.unregister(stream)
                        continue
                    buffer.extend(chunk)
                    if len(buffer) > limit:
                        raise AgentError("control-center backend output exceeded limit")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(process.args, timeout_seconds)
            process.wait(timeout=remaining)
        finally:
            selector.close()
            with contextlib.suppress(OSError):
                process.stdin.close()
            process.stdout.close()
            process.stderr.close()
        return bytes(streams[stdout_fd][1]), bytes(streams[stderr_fd][1])


class OperationController:
    def __init__(
        self,
        *,
        dispatch: Callable[[str, dict[str, Any]], dict[str, Any]] | None = None,
        schedule: Callable[..., Any],
    ) -> None:
        self._dispatch = dispatch or SubprocessToolDispatcher()
        self._schedule = schedule
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="codex-master-control")
        self._lock = threading.Lock()
        self._busy = False
        self._closed = False
        self._closing = False
        self._generation = 0

    @property
    def busy(self) -> bool:
        with self._lock:
            return self._busy

    def submit(
        self,
        tool_name: str,
        args: dict[str, Any],
        callback: Callable[[dict[str, Any]], Any],
    ) -> bool:
        with self._lock:
            if self._closed or self._closing or self._busy:
                return False
            prepare = getattr(self._dispatch, "prepare", None)
            if callable(prepare):
                prepare()
            self._busy = True
            self._generation += 1
            generation = self._generation
            try:
                future = self._executor.submit(self._execute, tool_name, dict(args))
            except Exception:
                abort_prepare = getattr(self._dispatch, "abort_prepare", None)
                if callable(abort_prepare):
                    abort_prepare()
                self._busy = False
                raise
        future.add_done_callback(lambda done: self._finished(generation, callback, done))
        return True

    def _execute(self, tool_name: str, args: dict[str, Any]) -> dict[str, Any]:
        try:
            result = self._dispatch(tool_name, args)
            if not isinstance(result, dict):
                raise AgentError("control-center backend returned invalid result")
            return result
        except Exception as exc:
            return public_error_payload(exc)

    def _finished(
        self,
        generation: int,
        callback: Callable[[dict[str, Any]], Any],
        future: Future[dict[str, Any]],
    ) -> None:
        try:
            result = future.result()
        except Exception as exc:
            result = public_error_payload(exc)
        with self._lock:
            if self._closed or generation != self._generation:
                return
        try:
            source_id = self._schedule(self._deliver, generation, callback, result)
        except BaseException:
            self._close_after_schedule_failure(generation)
            return
        if isinstance(source_id, bool) or not isinstance(source_id, int) or source_id <= 0:
            self._close_after_schedule_failure(generation)

    def _close_after_schedule_failure(self, generation: int) -> None:
        with self._lock:
            if self._closed or generation != self._generation:
                return
            self._busy = False
            self._closed = True
            self._closing = True
            self._generation += 1
        self._executor.shutdown(wait=False, cancel_futures=True)

    def _deliver(
        self,
        generation: int,
        callback: Callable[[dict[str, Any]], Any],
        result: dict[str, Any],
    ) -> bool:
        close_after_delivery = False
        with self._lock:
            if self._closed or generation != self._generation:
                return False
            self._busy = False
            if self._closing:
                self._closed = True
                self._generation += 1
                close_after_delivery = True
        if close_after_delivery:
            self._executor.shutdown(wait=False, cancel_futures=True)
            return False
        callback(result)
        return False

    def close(self) -> bool:
        with self._lock:
            if self._closed:
                return True
            if self._busy:
                self._closing = True
                return False
            self._closed = True
            self._closing = True
            self._generation += 1
        self._executor.shutdown(wait=False, cancel_futures=True)
        return True

    def cancel(self) -> bool:
        with self._lock:
            if not self._busy:
                return False
        cancel = getattr(self._dispatch, "cancel", None)
        return bool(cancel()) if callable(cancel) else False

    def abandon(self) -> None:
        try:
            self.cancel()
        except Exception:
            pass
        with self._lock:
            if self._closed:
                return
            self._busy = False
            self._closed = True
            self._closing = True
            self._generation += 1
        self._executor.shutdown(wait=False, cancel_futures=True)


def load_gtk() -> tuple[Any, Any]:
    try:
        import gi

        gi.require_version("Gtk", "3.0")
        from gi.repository import GLib, Gtk
    except (ImportError, ValueError) as exc:
        raise RuntimeError("GTK unavailable") from exc
    return Gtk, GLib


def action_block_reason(row: AgentRow, action: str) -> str | None:
    if action not in {"start", "stop"}:
        raise ValueError("unknown control-center action")
    allowed = row.can_start if action == "start" else row.can_stop
    if allowed:
        return None
    if row.issue:
        return "Status nicht verlässlich verfügbar"
    if action == "start" and row.activity_state == "running":
        return "Biene läuft bereits"
    if action == "stop" and row.activity_state != "running":
        return "Biene läuft nicht"
    if row.identity_state != "verified":
        return "Prozessidentität nicht verifiziert"
    if row.lease_state not in {"unclaimed", "expired"}:
        return "Biene besitzt aktive oder unlesbare Lease"
    if action == "start" and row.auth_state != "ready":
        return "Authentifizierung nicht einsatzbereit"
    if action == "start" and row.limit_state == "blocked":
        return "Geteilte Account-Reihe am Limit"
    if action == "start" and row.limit_state != "clear":
        return "Account-Limit nicht verlässlich bekannt"
    return "Aktion durch Sicherheitsvertrag gesperrt"


def row_summary(row: AgentRow) -> str:
    assignment = row.last_assignment_at_utc or "keiner"
    return (
        f"{row.agent} · {row.activity_state} · Auth {row.auth_state} · "
        f"Lease {row.lease_state} · Limit {row.limit_state} · Rolle {row.role}\n"
        f"Letzter Auftrag: {assignment}"
    )


class ControlCenterWindow:
    def __init__(self, Gtk: Any, GLib: Any, application: Any) -> None:
        self.Gtk = Gtk
        self.GLib = GLib
        self.page = 0
        self.last_page: StatusPage | None = None
        self.controller = OperationController(schedule=GLib.idle_add)
        self.tool_inputs: dict[str, tuple[FieldDescriptor, Any, Any, str]] = {}
        self.visible_tools: tuple[ToolDescriptor, ...] = ()
        self.selected_tool: ToolDescriptor | None = None
        self._suppress_tool_auto_run = False
        self._close_poll_id = 0
        self._page_names = (
            "Übersicht",
            "Werkzeuge",
            "Ollama/Modelle",
            "Ollama/Instanzen",
        )
        self.ollama_state: OllamaPageState | None = None
        self._ollama_models_payload: dict[str, object] | None = None
        self._ollama_plan: dict[str, object] | None = None
        self._ollama_apply_enabled = False
        self.ollama_model_checks: dict[str, Any] = {}
        try:
            self.tool_catalog = compile_catalog(teamleader_tool_catalog())
            self.catalog_error = None
        except (AgentError, CatalogError) as exc:
            self.tool_catalog = ()
            self.catalog_error = str(public_error_payload(exc).get("error", "Katalog nicht verfügbar"))[:160]
        self.window = Gtk.ApplicationWindow(application=application)
        self.window.set_title("Flottenmanagement – Steuerzentrale")
        self.window.set_default_size(980, 640)
        self.window.connect("delete-event", self._on_delete)

        header = Gtk.HeaderBar(title="Flottenmanagement", subtitle="Steuerzentrale")
        header.set_show_close_button(True)
        self.refresh_button = Gtk.Button.new_with_label("Aktualisieren")
        self.refresh_button.connect("clicked", lambda _button: self.refresh())
        header.pack_end(self.refresh_button)
        self.window.set_titlebar(header)

        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        outer.set_border_width(12)
        controls = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.search = Gtk.SearchEntry()
        self.search.set_placeholder_text("Bienen-ID oder Serie a/b/c/u")
        self.search.connect("activate", lambda _entry: self._apply_filter())
        controls.pack_start(self.search, True, True, 0)
        self.previous_button = Gtk.Button.new_with_label("Zurück")
        self.previous_button.connect("clicked", lambda _button: self._change_page(-1))
        controls.pack_start(self.previous_button, False, False, 0)
        self.next_button = Gtk.Button.new_with_label("Weiter")
        self.next_button.connect("clicked", lambda _button: self._change_page(1))
        controls.pack_start(self.next_button, False, False, 0)
        outer.pack_start(controls, False, False, 0)

        scroller = Gtk.ScrolledWindow()
        scroller.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        self.list_box = Gtk.ListBox()
        self.list_box.set_selection_mode(Gtk.SelectionMode.NONE)
        scroller.add(self.list_box)
        outer.pack_start(scroller, True, True, 0)
        self.status_label = Gtk.Label(label="Bereit")
        self.status_label.set_xalign(0.0)
        outer.pack_start(self.status_label, False, False, 0)
        self.notebook = Gtk.Notebook()
        self.notebook.append_page(outer, Gtk.Label(label="Übersicht"))
        self.notebook.append_page(self._build_tools_page(), Gtk.Label(label="Werkzeuge"))
        self.notebook.append_page(self._build_ollama_page(), Gtk.Label(label="Ollama"))
        self.window.add(self.notebook)

    def show(self) -> None:
        self.window.show_all()
        self.refresh()

    def page_names(self) -> set[str]:
        return set(self._page_names)

    def ollama_apply_sensitive(self) -> bool:
        return bool(self._ollama_apply_enabled)

    def render_ollama(self, state: OllamaPageState) -> None:
        if not isinstance(state, OllamaPageState):
            raise AgentError("control-center ollama page is invalid")
        self.ollama_state = state
        self._ollama_apply_enabled = bool(
            state.error_code is None and getattr(self, "_ollama_plan", None) is not None
        )
        if hasattr(self, "ollama_apply_button"):
            self.ollama_apply_button.set_sensitive(self._ollama_apply_enabled)
        if not hasattr(self, "ollama_models_box"):
            return
        for box in (self.ollama_models_box, self.ollama_instances_box):
            for child in box.get_children():
                box.remove(child)
        for row in state.models:
            label = self.Gtk.Label(
                label=(
                    f"{row.model_ref} · {row.provider_model_id} · "
                    f"installiert={row.installed} · Hive={row.hive_enabled} · "
                    f"simple_only={row.simple_only} · {', '.join(row.capabilities)}"
                )
            )
            label.set_xalign(0.0)
            self.ollama_models_box.pack_start(label, False, False, 0)
        self.ollama_model_checks.clear()
        for child in self.ollama_model_selector.get_children():
            self.ollama_model_selector.remove(child)
        for row in state.models:
            check = self.Gtk.CheckButton.new_with_label(row.model_ref)
            self.ollama_model_checks[row.model_ref] = check
            self.ollama_model_selector.pack_start(check, False, False, 0)
        for row in state.instances:
            label = self.Gtk.Label(
                label=(
                    f"{row.label} · {row.host_ref} · {row.lifecycle_state}/"
                    f"{row.readiness_state} · Modelle {', '.join(row.selected_model_refs)} · "
                    f"CPU {row.allowed_cpus}, Quote {row.cpu_quota_percent}%, "
                    f"Gewicht {row.cpu_weight}"
                )
            )
            label.set_xalign(0.0)
            self.ollama_instances_box.pack_start(label, False, False, 0)
        self.ollama_models_box.show_all()
        self.ollama_instances_box.show_all()
        self.ollama_model_selector.show_all()

    def _build_ollama_page(self) -> Any:
        Gtk = self.Gtk
        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        outer.set_border_width(12)
        refresh = Gtk.Button.new_with_label("Ollama aktualisieren")
        refresh.connect("clicked", lambda _button: self.refresh_ollama())
        outer.pack_start(refresh, False, False, 0)
        pages = Gtk.Notebook()

        models_page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        self.ollama_models_box = Gtk.Box(
            orientation=Gtk.Orientation.VERTICAL, spacing=4
        )
        models_scroller = Gtk.ScrolledWindow()
        models_scroller.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        models_scroller.add(self.ollama_models_box)
        models_page.pack_start(models_scroller, True, True, 0)
        pages.append_page(models_page, Gtk.Label(label="Modelle"))

        instances_page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        self.ollama_instances_box = Gtk.Box(
            orientation=Gtk.Orientation.VERTICAL, spacing=4
        )
        instances_scroller = Gtk.ScrolledWindow()
        instances_scroller.set_policy(
            Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC
        )
        instances_scroller.set_min_content_height(120)
        instances_scroller.add(self.ollama_instances_box)
        instances_page.pack_start(instances_scroller, True, True, 0)

        form = Gtk.Grid(column_spacing=8, row_spacing=6)
        fields = (
            ("Ref", "ollama_ref_entry", "quiet-runner"),
            ("Name", "ollama_label_entry", "Quiet Runner"),
            ("Executable", "ollama_executable_entry", "/usr/bin/ollama"),
            ("Modellpfad", "ollama_models_path_entry", "/var/lib/ollama/models"),
            ("AllowedCPUs", "ollama_cpus_entry", "0"),
        )
        for index, (title, attribute, default) in enumerate(fields):
            label = Gtk.Label(label=title)
            label.set_xalign(0.0)
            entry = Gtk.Entry()
            entry.set_text(default)
            entry.set_max_length(1024 if "path" in attribute or "executable" in attribute else 128)
            setattr(self, attribute, entry)
            form.attach(label, 0, index, 1, 1)
            form.attach(entry, 1, index, 1, 1)
        host_label = Gtk.Label(label="Host")
        host_label.set_xalign(0.0)
        self.ollama_host_combo = Gtk.ComboBoxText()
        self.ollama_host_combo.append("control-host", "control-host")
        self.ollama_host_combo.set_active(0)
        form.attach(host_label, 0, len(fields), 1, 1)
        form.attach(self.ollama_host_combo, 1, len(fields), 1, 1)
        self.ollama_quota_spin = Gtk.SpinButton.new_with_range(1, 10000, 1)
        self.ollama_quota_spin.set_value(100)
        self.ollama_weight_spin = Gtk.SpinButton.new_with_range(1, 10000, 1)
        self.ollama_weight_spin.set_value(100)
        form.attach(Gtk.Label(label="CPUQuota %"), 0, len(fields) + 1, 1, 1)
        form.attach(self.ollama_quota_spin, 1, len(fields) + 1, 1, 1)
        form.attach(Gtk.Label(label="CPUWeight"), 0, len(fields) + 2, 1, 1)
        form.attach(self.ollama_weight_spin, 1, len(fields) + 2, 1, 1)
        instances_page.pack_start(form, False, False, 0)

        self.ollama_model_selector = Gtk.Box(
            orientation=Gtk.Orientation.VERTICAL, spacing=3
        )
        instances_page.pack_start(
            Gtk.Label(label="Modelle der Instanz"), False, False, 0
        )
        instances_page.pack_start(self.ollama_model_selector, False, False, 0)
        actions = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        probe = Gtk.Button.new_with_label("Prüfen")
        probe.connect("clicked", lambda _button: self._probe_ollama())
        actions.pack_start(probe, False, False, 0)
        plan = Gtk.Button.new_with_label("Planen")
        plan.connect("clicked", lambda _button: self._plan_ollama())
        actions.pack_start(plan, False, False, 0)
        self.ollama_apply_button = Gtk.Button.new_with_label("Anwenden")
        self.ollama_apply_button.set_sensitive(False)
        self.ollama_apply_button.connect("clicked", lambda _button: self._apply_ollama())
        actions.pack_start(self.ollama_apply_button, False, False, 0)
        instances_page.pack_start(actions, False, False, 0)
        self.ollama_status_label = Gtk.Label(label="Noch nicht geladen")
        self.ollama_status_label.set_xalign(0.0)
        instances_page.pack_start(self.ollama_status_label, False, False, 0)
        self.ollama_plan_view = Gtk.TextView()
        self.ollama_plan_view.set_editable(False)
        self.ollama_plan_view.set_monospace(True)
        instances_page.pack_start(self.ollama_plan_view, False, True, 0)
        pages.append_page(instances_page, Gtk.Label(label="Instanzen"))
        outer.pack_start(pages, True, True, 0)
        return outer

    def refresh_ollama(self) -> None:
        self._ollama_plan = None
        self._ollama_apply_enabled = False
        if hasattr(self, "ollama_apply_button"):
            self.ollama_apply_button.set_sensitive(False)
        self._set_busy(True, "Ollama-Modelle werden geladen …")
        self.ollama_status_label.set_text("Ollama-Modelle werden geladen …")
        if not self.controller.submit(
            "fleet_ollama_models", {}, self._ollama_models_loaded
        ):
            self._set_busy(True, "Backendoperation läuft bereits")

    def _ollama_models_loaded(self, result: dict[str, Any]) -> None:
        if "error" in result:
            self.render_ollama(OllamaPageState(0, (), (), error_code="models_unavailable"))
            self._set_busy(False, "Ollama-Modelle nicht verfügbar")
            self.ollama_status_label.set_text("Ollama-Modelle nicht verfügbar")
            return
        self._ollama_models_payload = result
        self._set_busy(True, "Ollama-Instanzen werden geladen …")
        if not self.controller.submit(
            "fleet_ollama_instances", {}, self._ollama_instances_loaded
        ):
            self._set_busy(True, "Backendoperation läuft bereits")

    def _ollama_instances_loaded(self, result: dict[str, Any]) -> None:
        if "error" in result:
            state = OllamaPageState(0, (), (), error_code="instances_unavailable")
        else:
            try:
                state = parse_ollama_page(self._ollama_models_payload or {}, result)
            except FleetControlError:
                state = OllamaPageState(0, (), (), error_code="invalid_fleet_payload")
        self.render_ollama(state)
        if state.error_code is not None:
            text = f"Ollama-Vertrag verletzt: {state.error_code}"
        else:
            text = (
                f"Ollama: {len(state.models)} Modelle, "
                f"{len(state.instances)} Instanzen · Generation {state.generation}"
            )
        self._set_busy(False, text)
        self.ollama_status_label.set_text(text)

    def _plan_ollama(self) -> None:
        state = self.ollama_state
        if state is None or state.error_code is not None:
            self.ollama_status_label.set_text("Ollama-Status zuerst fehlerfrei laden")
            return
        host_ref = self.ollama_host_combo.get_active_id()
        selected_models = [
            ref for ref, check in self.ollama_model_checks.items() if check.get_active()
        ]
        try:
            arguments = ollama_instance_plan_args(
                ref=self.ollama_ref_entry.get_text(),
                label=self.ollama_label_entry.get_text(),
                host_ref=host_ref,
                ollama_executable=self.ollama_executable_entry.get_text(),
                models_directory=self.ollama_models_path_entry.get_text(),
                selected_model_refs=selected_models,
                allowed_cpus=self.ollama_cpus_entry.get_text(),
                cpu_quota_percent=self.ollama_quota_spin.get_value_as_int(),
                cpu_weight=self.ollama_weight_spin.get_value_as_int(),
                expected_generation=state.generation,
                idempotency_key=f"gui-plan-{secrets.token_hex(16)}",
            )
        except (FleetControlError, TypeError, ValueError):
            self.ollama_status_label.set_text("Ollama-Formular ungültig")
            return
        self._set_busy(True, "Ollama-Instanzplan wird erstellt …")
        if not self.controller.submit(
            "fleet_ollama_instance_plan", arguments, self._ollama_plan_finished
        ):
            self._set_busy(True, "Backendoperation läuft bereits")

    def _ollama_plan_finished(self, result: dict[str, Any]) -> None:
        state = self.ollama_state
        plan_id = result.get("plan_id")
        digest = result.get("plan_digest")
        generation = result.get("expected_generation")
        if (
            "error" in result
            or state is None
            or type(plan_id) is not str
            or not 1 <= len(plan_id) <= 128
            or type(digest) is not str
            or not 1 <= len(digest) <= 128
            or generation != state.generation
        ):
            self._ollama_plan = None
            self._ollama_apply_enabled = False
            self._set_busy(False, "Ollama-Instanzplan fehlgeschlagen")
            self.ollama_status_label.set_text("Ollama-Instanzplan fehlgeschlagen")
            return
        self._ollama_plan = {"plan_id": plan_id, "plan_digest": digest}
        self.ollama_plan_view.get_buffer().set_text(bounded_public_result_text(result))
        self._set_busy(False, "Ollama-Instanzplan bereit")
        self.ollama_status_label.set_text("Plan geprüft; Anwenden ist jetzt freigegeben")
        self.render_ollama(state)

    def _apply_ollama(self) -> None:
        state = self.ollama_state
        plan = self._ollama_plan
        if state is None or state.error_code is not None or plan is None:
            self.ollama_status_label.set_text("Kein gültiger Ollama-Plan")
            return
        if not self._confirm_message("Geprüften Ollama-Instanzplan jetzt anwenden?"):
            self.ollama_status_label.set_text("Ollama-Anwendung abgebrochen")
            return
        arguments = {
            "plan_id": plan["plan_id"],
            "expected_generation": state.generation,
            "idempotency_key": f"gui-apply-{secrets.token_hex(16)}",
            "plan_digest": plan["plan_digest"],
        }
        self._set_busy(True, "Ollama-Instanzplan wird angewendet …")
        if not self.controller.submit(
            "fleet_ollama_instance_apply",
            arguments,
            lambda result: self._ollama_mutation_finished("Anwendung", result),
        ):
            self._set_busy(True, "Backendoperation läuft bereits")

    def _probe_ollama(self) -> None:
        state = self.ollama_state
        instance_ref = self.ollama_ref_entry.get_text()
        if (
            state is None
            or state.error_code is not None
            or not isinstance(instance_ref, str)
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", instance_ref) is None
        ):
            self.ollama_status_label.set_text("Gültige Ollama-Instanz und Status erforderlich")
            return
        if not self._confirm_message(f"Ollama-Instanz {instance_ref} jetzt prüfen?"):
            self.ollama_status_label.set_text("Ollama-Prüfung abgebrochen")
            return
        arguments = {
            "instance_ref": instance_ref,
            "expected_generation": state.generation,
            "idempotency_key": f"gui-probe-{secrets.token_hex(16)}",
        }
        self._set_busy(True, "Ollama-Instanz wird geprüft …")
        if not self.controller.submit(
            "fleet_ollama_instance_probe",
            arguments,
            lambda result: self._ollama_mutation_finished("Prüfung", result),
        ):
            self._set_busy(True, "Backendoperation läuft bereits")

    def _ollama_mutation_finished(
        self, action: str, result: dict[str, Any]
    ) -> None:
        if "error" in result:
            self._set_busy(False, f"Ollama-{action} fehlgeschlagen")
            self.ollama_status_label.set_text(f"Ollama-{action} fehlgeschlagen")
            return
        self._ollama_plan = None
        self._set_busy(False, f"Ollama-{action} abgeschlossen")
        self.ollama_status_label.set_text(f"Ollama-{action} abgeschlossen")
        self.refresh_ollama()

    def _set_busy(self, busy: bool, text: str) -> None:
        self.refresh_button.set_sensitive(not busy)
        self.previous_button.set_sensitive(not busy and self.page > 0)
        self.next_button.set_sensitive(not busy and bool(self.last_page and self.last_page.truncated))
        self.search.set_sensitive(not busy)
        if hasattr(self, "tool_run_button"):
            self.tool_run_button.set_sensitive(
                not busy and bool(self.selected_tool and self.selected_tool.enabled)
            )
        if hasattr(self, "ollama_apply_button"):
            self.ollama_apply_button.set_sensitive(
                not busy and bool(getattr(self, "_ollama_apply_enabled", False))
            )
        self.status_label.set_text(text[:200])

    def _build_tools_page(self) -> Any:
        Gtk = self.Gtk
        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        outer.set_border_width(12)

        selectors = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.tool_category_combo = Gtk.ComboBoxText()
        for category in TOOL_CATEGORIES:
            self.tool_category_combo.append_text(category)
        self.tool_category_combo.set_active(0)
        self.tool_category_combo.connect("changed", lambda _combo: self._refresh_tool_selector())
        selectors.pack_start(self.tool_category_combo, False, False, 0)
        self.tool_selector = Gtk.ComboBoxText()
        self.tool_selector.connect("changed", lambda _combo: self._tool_selection_changed())
        selectors.pack_start(self.tool_selector, True, True, 0)
        outer.pack_start(selectors, False, False, 0)

        self.tool_risk_label = Gtk.Label(label="")
        self.tool_risk_label.set_xalign(0.0)
        outer.pack_start(self.tool_risk_label, False, False, 0)
        self.tool_description_label = Gtk.Label(label="")
        self.tool_description_label.set_xalign(0.0)
        self.tool_description_label.set_line_wrap(True)
        outer.pack_start(self.tool_description_label, False, False, 0)

        form_scroller = Gtk.ScrolledWindow()
        form_scroller.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        self.tool_form = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        form_scroller.add(self.tool_form)
        outer.pack_start(form_scroller, True, True, 0)

        action_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.tool_run_button = Gtk.Button.new_with_label("Ausführen")
        self.tool_run_button.connect("clicked", lambda _button: self._run_selected_tool())
        action_row.pack_end(self.tool_run_button, False, False, 0)
        self.tool_status_label = Gtk.Label(label="Bereit")
        self.tool_status_label.set_xalign(0.0)
        action_row.pack_start(self.tool_status_label, True, True, 0)
        outer.pack_start(action_row, False, False, 0)

        result_scroller = Gtk.ScrolledWindow()
        result_scroller.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        result_scroller.set_min_content_height(150)
        self.tool_result = Gtk.TextView()
        self.tool_result.set_editable(False)
        self.tool_result.set_cursor_visible(False)
        self.tool_result.set_monospace(True)
        result_scroller.add(self.tool_result)
        outer.pack_start(result_scroller, False, True, 0)

        if self.catalog_error:
            self.tool_status_label.set_text(f"Katalogfehler: {self.catalog_error}")
            self.tool_run_button.set_sensitive(False)
        else:
            self._refresh_tool_selector()
        return outer

    def _refresh_tool_selector(self) -> None:
        selected = self.tool_category_combo.get_active_text() or "Alle"
        self.visible_tools = tuple(
            tool for tool in self.tool_catalog if selected == "Alle" or tool_category(tool.name) == selected
        )
        self._suppress_tool_auto_run = True
        try:
            self.tool_selector.remove_all()
            for index, tool in enumerate(self.visible_tools):
                suffix = "" if tool.enabled else " · gesperrt"
                self.tool_selector.append(str(index), f"{tool.name} · {tool.risk.value}{suffix}")
            self.tool_selector.set_active(0 if self.visible_tools else -1)
        finally:
            self._suppress_tool_auto_run = False
        if not self.visible_tools:
            self.selected_tool = None
            self.tool_run_button.set_sensitive(False)

    def _tool_selection_changed(self) -> None:
        active = self.tool_selector.get_active_id()
        try:
            index = int(active) if active is not None else -1
        except ValueError:
            index = -1
        self.selected_tool = self.visible_tools[index] if 0 <= index < len(self.visible_tools) else None
        self._render_tool_form()
        if (
            not self._suppress_tool_auto_run
            and self.selected_tool is not None
            and self.selected_tool.enabled
            and not self.selected_tool.fields
        ):
            self._run_selected_tool()

    def _clear_tool_form(self) -> None:
        for child in self.tool_form.get_children():
            self.tool_form.remove(child)
        self.tool_inputs.clear()

    def _render_tool_form(self) -> None:
        self._clear_tool_form()
        tool = self.selected_tool
        if tool is None:
            self.tool_description_label.set_text("")
            self.tool_risk_label.set_text("")
            self.tool_run_button.set_sensitive(False)
            return
        self.tool_description_label.set_text(tool.description)
        risk_text = f"Risiko: {tool.risk.value}"
        if tool.disabled_reason:
            risk_text += f" · gesperrt: {tool.disabled_reason}"
        self.tool_risk_label.set_text(risk_text)
        self.tool_run_button.set_sensitive(tool.enabled and not self.controller.busy)
        if not tool.fields:
            empty = self.Gtk.Label(label="Keine Argumente")
            empty.set_xalign(0.0)
            self.tool_form.pack_start(empty, False, False, 0)
        for field in tool.fields:
            self._add_tool_field(field)
        self.tool_form.show_all()

    def _add_tool_field(self, field: FieldDescriptor) -> None:
        Gtk = self.Gtk
        row = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=3)
        heading = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        label = Gtk.Label(label=f"{field.name}{' *' if field.required else ''}")
        label.set_xalign(0.0)
        heading.pack_start(label, True, True, 0)
        use_field = Gtk.CheckButton.new_with_label("verwenden")
        use_field.set_active(field.required)
        use_field.set_sensitive(not field.required)
        heading.pack_end(use_field, False, False, 0)
        row.pack_start(heading, False, False, 0)
        if field.description:
            description = Gtk.Label(label=field.description)
            description.set_xalign(0.0)
            description.set_line_wrap(True)
            row.pack_start(description, False, False, 0)

        widget: Any
        widget_kind: str
        if field.enum:
            widget = Gtk.ComboBoxText()
            for index, value in enumerate(field.enum):
                widget.append(str(index), str(value))
            default_index = field.enum.index(field.default) if field.has_default and field.default in field.enum else 0
            widget.set_active(default_index)
            widget_kind = "enum"
        elif field.kind is FieldKind.BOOLEAN:
            widget = Gtk.CheckButton.new_with_label("aktiv")
            widget.set_active(bool(field.default) if field.has_default else False)
            widget_kind = "boolean"
        elif field.kind is FieldKind.INTEGER and field.minimum is not None and field.maximum is not None:
            adjustment = Gtk.Adjustment(
                value=int(field.default) if field.has_default else field.minimum,
                lower=field.minimum,
                upper=field.maximum,
                step_increment=1,
                page_increment=10,
                page_size=0,
            )
            widget = Gtk.SpinButton(adjustment=adjustment, climb_rate=1, digits=0)
            widget_kind = "integer_spin"
        elif field.kind is FieldKind.INTEGER:
            widget = Gtk.Entry()
            widget.set_max_length(32)
            if field.has_default:
                widget.set_text(str(field.default))
            widget_kind = "integer_entry"
        elif field.kind is FieldKind.STRING_ARRAY or field.name in LONG_TEXT_FIELDS:
            widget = Gtk.TextView()
            widget.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
            if field.has_default:
                default = "\n".join(field.default) if isinstance(field.default, tuple) else str(field.default)
                widget.get_buffer().set_text(default)
            field_scroller = Gtk.ScrolledWindow()
            field_scroller.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
            field_scroller.set_min_content_height(80)
            field_scroller.add(widget)
            row.pack_start(field_scroller, False, True, 0)
            widget_kind = "string_array" if field.kind is FieldKind.STRING_ARRAY else "text"
            self.tool_inputs[field.name] = (field, use_field, widget, widget_kind)
            self.tool_form.pack_start(row, False, False, 0)
            return
        else:
            widget = Gtk.Entry()
            widget.set_max_length(field.max_length or 12_000)
            if field.has_default:
                widget.set_text(str(field.default))
            widget_kind = "text"
        row.pack_start(widget, False, False, 0)
        self.tool_inputs[field.name] = (field, use_field, widget, widget_kind)
        self.tool_form.pack_start(row, False, False, 0)

    def _read_tool_arguments(self, tool: ToolDescriptor) -> dict[str, Any]:
        values: dict[str, Any] = {}
        for name, (field, use_field, widget, widget_kind) in self.tool_inputs.items():
            if not use_field.get_active():
                continue
            if widget_kind == "enum":
                active = widget.get_active_id()
                if active is None:
                    raise CatalogError(f"{name} ist nicht ausgewählt")
                values[name] = field.enum[int(active)]
            elif widget_kind == "boolean":
                values[name] = bool(widget.get_active())
            elif widget_kind == "integer_spin":
                values[name] = int(widget.get_value_as_int())
            elif widget_kind == "integer_entry":
                raw = widget.get_text()
                if not isinstance(raw, str) or not re.fullmatch(r"-?[0-9]+", raw):
                    raise CatalogError(f"{name} muss Ganzzahl sein")
                values[name] = int(raw)
            elif widget_kind in {"text", "string_array"} and hasattr(widget, "get_buffer"):
                buffer = widget.get_buffer()
                raw = buffer.get_text(buffer.get_start_iter(), buffer.get_end_iter(), True)
                values[name] = [line for line in raw.splitlines() if line] if widget_kind == "string_array" else raw
            else:
                values[name] = widget.get_text()
        return serialize_arguments(tool, values)

    def _set_tool_result(self, payload: Any) -> None:
        self.tool_result.get_buffer().set_text(bounded_public_result_text(payload))

    def _confirm_message(self, text: str) -> bool:
        dialog = self.Gtk.MessageDialog(
            transient_for=self.window,
            modal=True,
            message_type=self.Gtk.MessageType.WARNING,
            buttons=self.Gtk.ButtonsType.OK_CANCEL,
            text=text,
        )
        response = dialog.run()
        dialog.destroy()
        return response == self.Gtk.ResponseType.OK

    def _confirm_destructive(self, tool: ToolDescriptor) -> bool:
        phrase = f"AUSFÜHREN {tool.name}"
        dialog = self.Gtk.Dialog(title="Destruktive Aktion", transient_for=self.window, modal=True)
        dialog.add_button("Abbrechen", self.Gtk.ResponseType.CANCEL)
        dialog.add_button("Ausführen", self.Gtk.ResponseType.OK)
        box = dialog.get_content_area()
        box.set_spacing(8)
        box.add(self.Gtk.Label(label=f"Zur Bestätigung exakt eingeben:\n{phrase}"))
        entry = self.Gtk.Entry()
        entry.set_max_length(len(phrase))
        box.add(entry)
        dialog.show_all()
        response = dialog.run()
        accepted = response == self.Gtk.ResponseType.OK and entry.get_text() == phrase
        dialog.destroy()
        return accepted

    def _confirm_tool_run(self, tool: ToolDescriptor, risk: Risk, argument_count: int) -> bool:
        if risk is Risk.READ_ONLY:
            return True
        if risk is Risk.MUTATING:
            return self._confirm_message(f"{tool.name} mit {argument_count} Argument(en) ausführen?")
        if risk is Risk.BROAD:
            preview = self._confirm_message(
                f"Breite Aktion {tool.name}\nArgumente: {argument_count}\nZusammenfassung geprüft?"
            )
            return preview and self._confirm_message(f"{tool.name} jetzt wirklich ausführen?")
        if risk is Risk.DESTRUCTIVE:
            return self._confirm_destructive(tool)
        return False

    def _run_selected_tool(self) -> None:
        tool = self.selected_tool
        if tool is None or not tool.enabled:
            return
        try:
            arguments = self._read_tool_arguments(tool)
            risk = effective_risk(tool, arguments)
        except (CatalogError, ValueError, OverflowError) as exc:
            self.tool_status_label.set_text(f"Formularfehler: {str(exc)[:160]}")
            return
        if tool.name == "agent_pool_destroy_pool":
            if not self._confirm_message("Poolstatus als verpflichtende Vorschau laden?"):
                self.tool_status_label.set_text("Aktion abgebrochen")
                return
            preview_arguments = {
                key: value for key, value in arguments.items() if key in {"spec", "target_dir", "codex_bin"}
            }
            self._set_busy(True, "Pool-Löschvorschau wird geladen …")
            self.tool_status_label.set_text("Pool-Löschvorschau wird geladen …")
            if not self.controller.submit(
                "agent_pool_status",
                preview_arguments,
                lambda result, selected=tool, selected_args=arguments: self._destroy_preview_finished(
                    selected, selected_args, result
                ),
            ):
                self._set_busy(True, "Backendoperation läuft bereits")
            return
        if not self._confirm_tool_run(tool, risk, len(arguments)):
            self.tool_status_label.set_text("Aktion abgebrochen")
            return
        self._set_busy(True, f"Werkzeug {tool.name} läuft …")
        self.tool_status_label.set_text(f"{tool.name} läuft …")
        if not self.controller.submit(
            tool.name,
            arguments,
            lambda result, selected=tool, selected_risk=risk: self._tool_finished(selected, selected_risk, result),
        ):
            self._set_busy(True, "Backendoperation läuft bereits")

    def _destroy_preview_finished(
        self,
        tool: ToolDescriptor,
        arguments: dict[str, Any],
        preview: dict[str, Any],
    ) -> None:
        self._set_tool_result(preview)
        if "error" in preview:
            self._set_busy(False, "Pool-Löschvorschau fehlgeschlagen")
            self.tool_status_label.set_text("Pool-Löschvorschau fehlgeschlagen")
            return
        self._set_busy(False, "Pool-Löschvorschau geladen")
        self.tool_status_label.set_text("Pool-Löschvorschau geladen")
        if not self._confirm_destructive(tool):
            self.tool_status_label.set_text("Aktion nach Vorschau abgebrochen")
            return
        self._set_busy(True, f"Werkzeug {tool.name} läuft …")
        self.tool_status_label.set_text(f"{tool.name} läuft …")
        if not self.controller.submit(
            tool.name,
            arguments,
            lambda result, selected=tool: self._tool_finished(selected, Risk.DESTRUCTIVE, result),
        ):
            self._set_busy(True, "Backendoperation läuft bereits")

    def _tool_finished(self, tool: ToolDescriptor, risk: Risk, result: dict[str, Any]) -> None:
        self._set_tool_result(result)
        if "error" in result:
            self._set_busy(False, f"{tool.name}: fehlgeschlagen")
            self.tool_status_label.set_text(f"{tool.name}: fehlgeschlagen")
            return
        self._set_busy(False, f"{tool.name}: abgeschlossen")
        self.tool_status_label.set_text(f"{tool.name}: abgeschlossen")
        if risk is not Risk.READ_ONLY:
            self.refresh()

    def _filter_text(self) -> str:
        value = self.search.get_text()
        return value if isinstance(value, str) else ""

    def _apply_filter(self) -> None:
        self.page = 0
        self.refresh()

    def _change_page(self, delta: int) -> None:
        next_page = max(0, self.page + delta)
        if next_page == self.page:
            return
        self.page = next_page
        self.refresh()

    def refresh(self) -> None:
        try:
            args = status_query(self._filter_text(), self.page)
        except AgentError:
            self._set_busy(False, "Filter ungültig: erlaubt sind a, b, c oder konkrete IDs wie a12")
            return
        self._set_busy(True, "Status wird geladen …")
        if not self.controller.submit("agent_status", args, self._status_loaded):
            self._set_busy(True, "Backendoperation läuft bereits")

    def _status_loaded(self, result: dict[str, Any]) -> None:
        if "error" in result:
            self._set_busy(False, f"Statusfehler: {str(result['error'])[:160]}")
            return
        try:
            page = normalize_status_page(result)
        except AgentError:
            self._set_busy(False, "Backendstatus verletzt Vertrag")
            return
        self.last_page = page
        self._render_page(page)
        first = page.agents_offset + 1 if page.result_count else 0
        last = page.agents_offset + page.result_count
        self._set_busy(False, f"Bienen {first}–{last} von {page.total_count}")

    def _render_page(self, page: StatusPage) -> None:
        for child in self.list_box.get_children():
            self.list_box.remove(child)
        for row in page.rows:
            item = self.Gtk.ListBoxRow()
            box = self.Gtk.Box(orientation=self.Gtk.Orientation.HORIZONTAL, spacing=12)
            label = self.Gtk.Label(label=row_summary(row))
            label.set_xalign(0.0)
            box.pack_start(label, True, True, 0)
            for action, title in (("stop", "Stoppen"), ("start", "Starten")):
                button = self.Gtk.Button.new_with_label(title)
                reason = action_block_reason(row, action)
                button.set_sensitive(reason is None)
                if reason is not None:
                    button.set_tooltip_text(reason)
                button.connect(
                    "clicked",
                    lambda _button, selected=action, agent=row.agent: self._confirm_mutation(selected, agent),
                )
                box.pack_end(button, False, False, 0)
            item.add(box)
            self.list_box.add(item)
        self.list_box.show_all()

    def _confirm_mutation(self, action: str, agent: str) -> None:
        verb = "starten" if action == "start" else "stoppen"
        dialog = self.Gtk.MessageDialog(
            transient_for=self.window,
            modal=True,
            message_type=self.Gtk.MessageType.WARNING,
            buttons=self.Gtk.ButtonsType.OK_CANCEL,
            text=f"{agent} wirklich {verb}?",
        )
        response = dialog.run()
        dialog.destroy()
        if response != self.Gtk.ResponseType.OK:
            return
        tool = "agent_start" if action == "start" else "agent_stop"
        args = {"agent": agent}
        if action == "start":
            args["cwd"] = str(Path.home())
        self._set_busy(True, f"{agent} wird {verb} …")
        if not self.controller.submit(tool, args, lambda result: self._mutation_finished(action, agent, result)):
            self._set_busy(True, "Backendoperation läuft bereits")

    def _mutation_finished(self, action: str, agent: str, result: dict[str, Any]) -> None:
        if "error" in result:
            self._set_busy(False, f"{agent}: Aktion fehlgeschlagen: {str(result['error'])[:120]}")
            return
        verb = "Start" if action == "start" else "Stop"
        self._set_busy(False, f"{agent}: {verb} abgeschlossen; Status wird geprüft")
        self.refresh()

    def _on_delete(self, _window: Any, _event: Any) -> bool:
        if self.controller.close():
            if self._close_poll_id:
                try:
                    self.GLib.source_remove(self._close_poll_id)
                except Exception:
                    pass
                self._close_poll_id = 0
            return False
        else:
            cancelled = self.controller.cancel()
            detail = "Abbruch angefordert" if cancelled else "warte auf begrenztes Backendzeitlimit"
            self.status_label.set_text(f"Backendoperation läuft; {detail}")
            self.tool_status_label.set_text(f"Backendoperation läuft; {detail}")
            if not self._close_poll_id:
                try:
                    source_id = self.GLib.timeout_add(50, self._poll_close)
                    self._close_poll_id = (
                        source_id
                        if not isinstance(source_id, bool)
                        and isinstance(source_id, int)
                        and source_id > 0
                        else 0
                    )
                except Exception:
                    self._close_poll_id = 0
                if not self._close_poll_id:
                    try:
                        self.controller.abandon()
                    except Exception:
                        pass
                    return False
            return True

    def _poll_close(self) -> bool:
        if self.controller.busy:
            self.controller.cancel()
            return True
        if not self.controller.close():
            self.controller.cancel()
            return True
        self._close_poll_id = 0
        self.window.destroy()
        return False


def launch_gtk_application(args: list[str]) -> int:
    try:
        Gtk, GLib = load_gtk()
    except RuntimeError as exc:
        raise AgentError("control-center GTK is unavailable") from exc
    initialized, _gtk_args = Gtk.init_check(["codex-master-control-center", *args])
    if not initialized:
        raise AgentError("control-center display is unavailable")
    application = Gtk.Application(application_id=APPLICATION_ID)
    holder: dict[str, ControlCenterWindow] = {}

    def activate(app: Any) -> None:
        window = holder.get("window")
        if window is None:
            window = ControlCenterWindow(Gtk, GLib, app)
            holder["window"] = window
        window.show()

    application.connect("activate", activate)
    return int(application.run(["codex-master-control-center", *args]))


def run_control_center(args: list[str] | None = None) -> int:
    assert_install_context_allows_master_registration()
    require_teamleader_tool_access()
    return launch_gtk_application(list(args or []))
