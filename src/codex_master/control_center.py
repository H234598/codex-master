"""GTK control center for codex-master.

Business state stays independent from GTK so contract and concurrency behavior
remain headless-testable.
"""

from __future__ import annotations

import re
import threading
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Callable

from codex_master.server import (
    AgentError,
    assert_install_context_allows_master_registration,
    call_validated_tool,
    public_error_payload,
)


APPLICATION_ID = "de.teladi.CodexMaster.ControlCenter"
PAGE_SIZE = 20
MAX_FILTER_CHARS = 64
MAX_PAGE_ROWS = 20
AGENT_ID_RE = re.compile(r"^[abc](?:[1-9]|[1-9][0-9]|100)$")
SERIES_FILTER_RE = re.compile(r"^[abc]$")
STATUS_PAGE_FIELDS = {
    "results",
    "result_count",
    "total_count",
    "agents_offset",
    "agents_limit",
    "truncated",
    "raw_output",
}


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


class OperationController:
    def __init__(
        self,
        *,
        dispatch: Callable[[str, dict[str, Any]], dict[str, Any]] = call_validated_tool,
        schedule: Callable[..., Any],
    ) -> None:
        self._dispatch = dispatch
        self._schedule = schedule
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="codex-master-control")
        self._lock = threading.Lock()
        self._busy = False
        self._closed = False
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
            if self._closed or self._busy:
                return False
            self._busy = True
            self._generation += 1
            generation = self._generation
        future = self._executor.submit(self._execute, tool_name, dict(args))
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
        self._schedule(self._deliver, generation, callback, result)

    def _deliver(
        self,
        generation: int,
        callback: Callable[[dict[str, Any]], Any],
        result: dict[str, Any],
    ) -> bool:
        with self._lock:
            if self._closed or generation != self._generation:
                return False
            self._busy = False
        callback(result)
        return False

    def close(self) -> bool:
        with self._lock:
            if self._busy:
                return False
            if self._closed:
                return True
            self._closed = True
            self._generation += 1
        self._executor.shutdown(wait=False, cancel_futures=True)
        return True


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


class ControlCenterWindow:
    def __init__(self, Gtk: Any, GLib: Any, application: Any) -> None:
        self.Gtk = Gtk
        self.GLib = GLib
        self.page = 0
        self.last_page: StatusPage | None = None
        self.controller = OperationController(schedule=GLib.idle_add)
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
        self.search.set_placeholder_text("Bienen-ID oder Serie a/b/c")
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
        self.window.add(outer)

    def show(self) -> None:
        self.window.show_all()
        self.refresh()

    def _set_busy(self, busy: bool, text: str) -> None:
        self.refresh_button.set_sensitive(not busy)
        self.previous_button.set_sensitive(not busy and self.page > 0)
        self.next_button.set_sensitive(not busy and bool(self.last_page and self.last_page.truncated))
        self.search.set_sensitive(not busy)
        self.status_label.set_text(text[:200])

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
            summary = (
                f"{row.agent} · {row.activity_state} · Auth {row.auth_state} · "
                f"Lease {row.lease_state} · Limit {row.limit_state} · Rolle {row.role}"
            )
            label = self.Gtk.Label(label=summary)
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
        if not self.controller.close():
            self.status_label.set_text("Backendoperation läuft; Fenster bleibt bis Abschluss geöffnet")
            return True
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
    return launch_gtk_application(list(args or []))
