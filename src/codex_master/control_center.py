"""Headless control-center controller used by GTK adapters.

The module deliberately has no GTK dependency.  A UI can bind its widgets to
this controller while keeping fleet parsing, generation checks, serialization,
and secret lifetime testable in a plain Python process.
"""

from __future__ import annotations

import re
import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from .fleet_control import (
    FleetAccountRow,
    FleetControlError,
    FleetPageState,
    FleetSeriesRow,
    account_secret_args,
    account_upsert_args,
    parse_fleet_page,
    series_apply_args,
    series_plan_args,
)


SERIES_FILTER_RE = re.compile(r"^[a-z]$")
AGENT_ID_RE = re.compile(r"^[a-z](?:[1-9]|[1-9][0-9]|100)$")
ACCOUNT_ID_RE = re.compile(r"^[a-z][a-z0-9-]{0,63}$")
FLEET_CATEGORY = "Serien & Accounts"


class FleetControlCenterError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class FleetControlView:
    state: FleetPageState
    dry_run_generation: int | None = None
    busy: bool = False
    dry_run_plan: tuple[tuple[str, str], ...] | None = None


def _series_plan_key(args: Mapping[str, object]) -> tuple[tuple[str, str], ...]:
    return tuple(
        (key, repr(args[key]))
        for key in sorted(args)
        if key != "expected_generation"
    )


class FleetControlCenter:
    """Small serialized controller for a GTK page or another local UI."""

    def __init__(self, dispatch: Callable[[str, dict[str, object]], Mapping[str, object]]) -> None:
        self._dispatch = dispatch
        self._lock = threading.Lock()
        self._view = FleetControlView(FleetPageState(0, (), ()))

    @property
    def view(self) -> FleetControlView:
        return self._view

    @property
    def state(self) -> FleetPageState:
        return self._view.state

    def refresh(self, accounts_payload: object, series_payload: object) -> FleetPageState:
        state = parse_fleet_page(accounts_payload, series_payload)
        self._view = FleetControlView(state)
        return state

    def _run(self, tool: str, args: dict[str, object]) -> Mapping[str, object]:
        if not self._lock.acquire(blocking=False):
            raise FleetControlCenterError("fleet_operation_busy")
        self._view = FleetControlView(
            self._view.state, self._view.dry_run_generation, True, self._view.dry_run_plan,
        )
        try:
            return self._dispatch(tool, args)
        finally:
            self._view = FleetControlView(
                self._view.state, self._view.dry_run_generation, False, self._view.dry_run_plan,
            )
            self._lock.release()

    def upsert_account(
        self, *, account_id: str, label: str, provider: str, auth_kind: str,
        enabled: bool, expected_generation: int,
    ) -> Mapping[str, object]:
        return self._run("fleet_account_upsert", account_upsert_args(
            account_id=account_id, label=label, provider=provider, auth_kind=auth_kind,
            enabled=enabled, expected_generation=expected_generation,
        ))

    def set_account_secret(self, *, account_id: str, secret: str, expected_generation: int) -> Mapping[str, object]:
        args = account_secret_args(
            account_id=account_id, secret=secret, expected_generation=expected_generation,
        )
        try:
            return self._run("fleet_account_set_secret", args)
        finally:
            # The dispatcher receives the only mutable argument container.  It
            # is scrubbed even when validation, dispatch, or transport fails.
            args["secret"] = ""

    def plan_series(
        self, *, prefix: str, count: int, runner: str, provider: str, model: str,
        account_id: str | None, enabled: bool, expected_generation: int,
        confirmed_remove_ids: list[str] | tuple[str, ...] | None = None,
    ) -> Mapping[str, object]:
        result = self._run("fleet_series_plan", series_plan_args(
            prefix=prefix, count=count, runner=runner, provider=provider, model=model,
            account_id=account_id, enabled=enabled, expected_generation=expected_generation,
            confirmed_remove_ids=confirmed_remove_ids,
        ))
        candidate_generation = result.get("next_generation")
        if not isinstance(candidate_generation, int):
            candidate_generation = result.get("generation")
        planned_args = series_plan_args(
            prefix=prefix, count=count, runner=runner, provider=provider, model=model,
            account_id=account_id, enabled=enabled, expected_generation=expected_generation,
            confirmed_remove_ids=confirmed_remove_ids,
        )
        self._view = FleetControlView(
            self._view.state,
            candidate_generation if isinstance(candidate_generation, int) else None,
            False,
            _series_plan_key(planned_args),
        )
        return result

    def apply_series(
        self, *, prefix: str, count: int, runner: str, provider: str, model: str,
        account_id: str | None, enabled: bool, expected_generation: int,
        confirmed_remove_ids: list[str] | tuple[str, ...] | None = None,
    ) -> Mapping[str, object]:
        applied_args = series_apply_args(
            prefix=prefix, count=count, runner=runner, provider=provider, model=model,
            account_id=account_id, enabled=enabled, expected_generation=expected_generation,
            confirmed_remove_ids=confirmed_remove_ids,
        )
        if (
            self._view.dry_run_generation != expected_generation
            or self._view.dry_run_plan != _series_plan_key(applied_args)
        ):
            raise FleetControlCenterError("fleet_dry_run_stale")
        return self._run("fleet_series_apply", applied_args)

    def disable_account(self, *, account_id: str, expected_generation: int) -> Mapping[str, object]:
        if not ACCOUNT_ID_RE.fullmatch(account_id):
            raise FleetControlCenterError("invalid_account")
        return self._run("fleet_account_disable", {
            "account_id": account_id,
            "expected_generation": expected_generation,
        })

    def delete_account(self, *, account_id: str, expected_generation: int) -> Mapping[str, object]:
        if not ACCOUNT_ID_RE.fullmatch(account_id):
            raise FleetControlCenterError("invalid_account")
        return self._run("fleet_account_delete", {
            "account_id": account_id,
            "expected_generation": expected_generation,
        })

    def disable_series(self, *, prefix: str, expected_generation: int) -> Mapping[str, object]:
        if not SERIES_FILTER_RE.fullmatch(prefix):
            raise FleetControlCenterError("invalid_series")
        return self._run("fleet_series_disable", {
            "prefix": prefix,
            "expected_generation": expected_generation,
        })

    def delete_series(
        self, *, prefix: str, expected_generation: int, confirmed_remove_ids: list[str] | tuple[str, ...],
    ) -> Mapping[str, object]:
        if not SERIES_FILTER_RE.fullmatch(prefix):
            raise FleetControlCenterError("invalid_series")
        return self._run("fleet_series_delete", {
            "prefix": prefix,
            "expected_generation": expected_generation,
            "confirmed_remove_ids": list(confirmed_remove_ids),
        })


def _load_gtk() -> Any:
    """Load GTK only for a desktop caller; importing this module stays headless-safe."""

    try:
        import gi

        gi.require_version("Gtk", "3.0")
        from gi.repository import Gtk
    except (ImportError, ValueError) as exc:
        raise FleetControlCenterError("gtk_unavailable") from exc
    return Gtk


class GtkFleetControlPage:
    """Small GTK3 adapter around :class:`FleetControlCenter`.

    The adapter owns widgets only. Parsing, validation, serialization and
    secret clearing remain in the GTK-free controller so tests never need a
    display server or GI bindings.
    """

    def __init__(self, controller: FleetControlCenter) -> None:
        self.controller = controller
        self._Gtk = _load_gtk()
        self.widget = self._build()

    @staticmethod
    def _entry(Gtk: Any, placeholder: str) -> Any:
        entry = Gtk.Entry()
        entry.set_placeholder_text(placeholder)
        return entry

    @staticmethod
    def _tree(Gtk: Any, store: Any, titles: tuple[str, ...]) -> Any:
        tree = Gtk.TreeView(model=store)
        for index, title in enumerate(titles):
            column = Gtk.TreeViewColumn(title, Gtk.CellRendererText(), text=index)
            column.set_resizable(True)
            tree.append_column(column)
        return tree

    def _build(self) -> Any:
        Gtk = self._Gtk
        root = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        root.set_border_width(8)
        root.pack_start(Gtk.Label(label=FLEET_CATEGORY, xalign=0), False, False, 0)

        split = Gtk.Paned(orientation=Gtk.Orientation.HORIZONTAL)
        self.account_store = Gtk.ListStore(str, str, str, str, str)
        self.series_store = Gtk.ListStore(str, str, str, str, str, str)
        split.add1(self._tree(Gtk, self.account_store, ("Account", "Provider", "Status", "Limit", "Enabled")))
        split.add2(self._tree(Gtk, self.series_store, ("Prefix", "Name", "Count", "Runner", "Provider", "Eligibility")))
        root.pack_start(split, True, True, 0)

        form = Gtk.Grid(column_spacing=6, row_spacing=6)
        form.set_column_homogeneous(False)
        self.account_id_entry = self._entry(Gtk, "Account-ID")
        self.label_entry = self._entry(Gtk, "Label")
        self.provider_entry = self._entry(Gtk, "Provider")
        self.secret_entry = self._entry(Gtk, "Secret (wird sofort geleert)")
        self.secret_entry.set_visibility(False)
        self.prefix_entry = self._entry(Gtk, "Serienprefix a-z")
        self.count_entry = self._entry(Gtk, "Count 1-100")
        self.runner_entry = self._entry(Gtk, "Runner")
        self.series_provider_entry = self._entry(Gtk, "Provider")
        self.model_entry = self._entry(Gtk, "Model")
        self.series_account_entry = self._entry(Gtk, "Account-ID oder leer")
        fields = (
            ("Account", self.account_id_entry), ("Label", self.label_entry),
            ("Provider", self.provider_entry), ("Secret", self.secret_entry),
            ("Prefix", self.prefix_entry), ("Count", self.count_entry),
            ("Runner", self.runner_entry), ("Series provider", self.series_provider_entry),
            ("Model", self.model_entry), ("Series account", self.series_account_entry),
        )
        for row, (label, entry) in enumerate(fields):
            form.attach(Gtk.Label(label=label, xalign=0), 0, row, 1, 1)
            form.attach(entry, 1, row, 1, 1)
        root.pack_start(form, False, False, 0)

        buttons = Gtk.Box(spacing=6)
        for label, callback in (
            ("Neu", self._clear_form),
            ("Account speichern", self._upsert_account),
            ("Secret setzen", self._set_secret),
            ("Account deaktivieren", self._disable_account),
            ("Account löschen", self._delete_account),
            ("Dry-Run", self._plan_series),
            ("Anwenden", self._apply_series),
            ("Serie deaktivieren", self._disable_series),
        ):
            button = Gtk.Button(label=label)
            button.connect("clicked", callback)
            buttons.pack_start(button, False, False, 0)
        root.pack_start(buttons, False, False, 0)
        self.status_label = Gtk.Label(label="", xalign=0)
        root.pack_start(self.status_label, False, False, 0)
        self.refresh(self.controller.state)
        return root

    def refresh(self, state: FleetPageState | None = None) -> None:
        state = state or self.controller.state
        self.account_store.clear()
        for row in state.accounts:
            self.account_store.append((row.account_id, row.provider, row.auth_status, row.limit_state, str(row.enabled)))
        self.series_store.clear()
        for row in state.series:
            self.series_store.append((row.prefix, row.display_name, str(row.count), row.runner, row.provider, row.eligibility))
        self.status_label.set_text(state.error_code or "")

    def _result(self, action: Callable[[], Mapping[str, object]]) -> None:
        try:
            result = action()
        except (FleetControlError, FleetControlCenterError) as exc:
            self.status_label.set_text(str(exc)[:64])
        except Exception:
            self.status_label.set_text("fleet_operation_failed")
        else:
            self.status_label.set_text(str(result.get("status", result.get("generation", "ok")))[:160])
            self.refresh()

    def _confirm(self, message: str, action: Callable[[], None]) -> None:
        Gtk = self._Gtk
        dialog = Gtk.MessageDialog(
            transient_for=self.widget.get_toplevel(),
            flags=Gtk.DialogFlags.MODAL,
            message_type=Gtk.MessageType.WARNING,
            buttons=Gtk.ButtonsType.YES_NO,
            text=message,
        )
        try:
            if dialog.run() == Gtk.ResponseType.YES:
                action()
        finally:
            dialog.destroy()

    def _clear_form(self, _button: Any) -> None:
        for entry in (
            self.account_id_entry, self.label_entry, self.provider_entry, self.secret_entry,
            self.prefix_entry, self.count_entry, self.runner_entry, self.series_provider_entry,
            self.model_entry, self.series_account_entry,
        ):
            entry.set_text("")

    def _upsert_account(self, _button: Any) -> None:
        provider = self.provider_entry.get_text().strip()
        auth_kind = "chatgpt_session" if provider == "openai_chatgpt" else "api_key"
        self._result(lambda: self.controller.upsert_account(
            account_id=self.account_id_entry.get_text().strip(), label=self.label_entry.get_text().strip(),
            provider=provider, auth_kind=auth_kind, enabled=True,
            expected_generation=self.controller.state.generation,
        ))

    def _set_secret(self, _button: Any) -> None:
        secret = self.secret_entry.get_text()
        self.secret_entry.set_text("")
        self._result(lambda: self.controller.set_account_secret(
            account_id=self.account_id_entry.get_text().strip(), secret=secret,
            expected_generation=self.controller.state.generation,
        ))

    def _disable_account(self, _button: Any) -> None:
        account_id = self.account_id_entry.get_text().strip()
        self._confirm("Account deaktivieren?", lambda: self._result(lambda: self.controller.disable_account(
            account_id=account_id, expected_generation=self.controller.state.generation,
        )))

    def _delete_account(self, _button: Any) -> None:
        account_id = self.account_id_entry.get_text().strip()
        self._confirm("Account löschen?", lambda: self._result(lambda: self.controller.delete_account(
            account_id=account_id, expected_generation=self.controller.state.generation,
        )))

    def _series_values(self) -> dict[str, object]:
        return {
            "prefix": self.prefix_entry.get_text().strip(),
            "count": int(self.count_entry.get_text().strip()),
            "runner": self.runner_entry.get_text().strip(),
            "provider": self.series_provider_entry.get_text().strip(),
            "model": self.model_entry.get_text().strip(),
            "account_id": self.series_account_entry.get_text().strip() or None,
            "enabled": True,
        }

    def _plan_series(self, _button: Any) -> None:
        try:
            values = self._series_values()
        except (TypeError, ValueError):
            self.status_label.set_text("invalid_series")
            return
        self._result(lambda: self.controller.plan_series(**values, expected_generation=self.controller.state.generation))

    def _apply_series(self, _button: Any) -> None:
        try:
            values = self._series_values()
        except (TypeError, ValueError):
            self.status_label.set_text("invalid_series")
            return
        generation = self.controller.view.dry_run_generation
        if generation is None:
            self.status_label.set_text("fleet_dry_run_required")
            return
        self._result(lambda: self.controller.apply_series(**values, expected_generation=generation))

    def _disable_series(self, _button: Any) -> None:
        prefix = self.prefix_entry.get_text().strip()
        self._confirm("Serie deaktivieren?", lambda: self._result(lambda: self.controller.disable_series(
            prefix=prefix, expected_generation=self.controller.state.generation,
        )))


def build_gtk_page(controller: FleetControlCenter) -> Any:
    """Build the optional desktop page, raising a bounded error without GTK."""

    return GtkFleetControlPage(controller).widget


__all__ = [
    "ACCOUNT_ID_RE",
    "AGENT_ID_RE",
    "FLEET_CATEGORY",
    "SERIES_FILTER_RE",
    "FleetAccountRow",
    "FleetControlCenter",
    "FleetControlCenterError",
    "FleetControlError",
    "FleetControlView",
    "FleetPageState",
    "FleetSeriesRow",
    "GtkFleetControlPage",
    "build_gtk_page",
]
