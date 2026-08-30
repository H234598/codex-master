import json
import sys
import threading
import time
import unittest
from unittest.mock import Mock, patch

from codex_master import control_center
from codex_master.control_catalog import RISK_BY_TOOL
from codex_master.fleet_control import OllamaPageState
from codex_master.server import AgentError


class ControlCenterViewModelTest(unittest.TestCase):
    @staticmethod
    def _ollama_payloads() -> tuple[dict, dict]:
        return (
            {
                "models": [
                    {
                        "ref": "model-a",
                        "provider_model_id": "granite:latest",
                        "installed": True,
                        "hive_enabled": True,
                        "simple_only": True,
                        "capabilities": ["chat"],
                        "evidence_at_utc": "2026-08-30T12:00:00Z",
                    }
                ]
            },
            {"generation": 7, "instances": []},
        )

    def _status_result(self, *, running: bool = False, blocked: bool = False) -> dict:
        return {
            "agent": "a1",
            "running": running,
            "session": "SECRET_SESSION",
            "pid": 123 if running else None,
            "auth": {
                "authenticated": True,
                "auth_state": "present_regular",
                "auth_mode": "chatgpt",
                "token_state": "unexpired",
            },
            "lease": {
                "state": "unclaimed",
                "lease_id": "SECRET_LEASE_ID",
                "holder": "SECRET_HOLDER",
            },
            "identity_guard": {
                "ok": True,
                "state": "verified",
            },
            "usage_watchdog": {
                "state": "blocked" if blocked else "clear",
                "blocked": blocked,
                "blocked_until_utc": "2026-08-03T15:00:00+00:00" if blocked else None,
                "account": "SECRET_ACCOUNT",
            },
            "last_assignment": {
                "assignment_id": "SECRET_ASSIGNMENT_ID",
                "created_at_utc": "2026-08-03T12:00:00+00:00",
                "role": "arbeitsbiene",
            },
        }

    def _page(self, result: dict) -> dict:
        return {
            "results": [result],
            "result_count": 1,
            "total_count": 300,
            "agents_offset": 0,
            "agents_limit": 20,
            "truncated": True,
            "raw_output": "not_returned",
        }

    def test_normalizes_status_without_retaining_private_fields(self) -> None:
        page = control_center.normalize_status_page(self._page(self._status_result()))

        self.assertEqual(page.total_count, 300)
        self.assertEqual(page.rows[0].agent, "a1")
        self.assertTrue(page.rows[0].can_start)
        self.assertFalse(page.rows[0].can_stop)
        encoded = json.dumps(page.to_public_dict(), sort_keys=True)
        for secret in (
            "SECRET_SESSION",
            "SECRET_LEASE_ID",
            "SECRET_HOLDER",
            "SECRET_ACCOUNT",
            "SECRET_ASSIGNMENT_ID",
        ):
            self.assertNotIn(secret, encoded)

    def test_stop_is_limit_independent_but_requires_verified_identity_and_free_lease(self) -> None:
        blocked_running = self._status_result(running=True, blocked=True)
        page = control_center.normalize_status_page(self._page(blocked_running))

        self.assertTrue(page.rows[0].can_stop)
        self.assertFalse(page.rows[0].can_start)

        blocked_running["identity_guard"]["ok"] = False
        page = control_center.normalize_status_page(self._page(blocked_running))
        self.assertFalse(page.rows[0].can_stop)

    def test_rejects_oversized_or_inconsistent_status_pages(self) -> None:
        payload = self._page(self._status_result())
        payload["results"] = [self._status_result() for _ in range(21)]
        payload["result_count"] = 21
        with self.assertRaisesRegex(AgentError, "status page"):
            control_center.normalize_status_page(payload)

        payload = self._page(self._status_result())
        payload["result_count"] = 2
        with self.assertRaisesRegex(AgentError, "status page"):
            control_center.normalize_status_page(payload)

    def test_status_query_supports_all_series_and_concrete_ids_only(self) -> None:
        self.assertEqual(
            control_center.status_query("", 2),
            {"agent": "all", "agents_offset": 40, "agents_limit": 20},
        )
        self.assertEqual(
            control_center.status_query(" A ", 1),
            {"agent": "a-series", "agents_offset": 20, "agents_limit": 20},
        )
        self.assertEqual(
            control_center.status_query("c100", 9),
            {"agent": "c100", "agents_offset": 0, "agents_limit": 20},
        )
        for invalid in ("a0", "all", "../../x", "a1\nstop", "x" * 65):
            with self.subTest(value=invalid):
                with self.assertRaisesRegex(AgentError, "filter"):
                    control_center.status_query(invalid, 0)

    def test_every_runtime_tool_has_stable_functional_category(self) -> None:
        categories = {control_center.tool_category(name) for name in RISK_BY_TOOL}
        self.assertEqual(
            categories,
            {"Aufträge", "Serien", "Auth & Limits", "Agentinnen", "Diagnose"},
        )
        self.assertEqual(control_center.tool_category("agent_pool_copy_auth"), "Auth & Limits")

    def test_control_center_declares_ollama_models_and_instances_pages(self) -> None:
        window = control_center.ControlCenterWindow.__new__(
            control_center.ControlCenterWindow
        )
        window._page_names = (
            "Übersicht",
            "Werkzeuge",
            "Ollama/Modelle",
            "Ollama/Instanzen",
        )

        self.assertGreaterEqual(
            window.page_names(),
            {"Übersicht", "Werkzeuge", "Ollama/Modelle", "Ollama/Instanzen"},
        )

    def test_stale_ollama_state_disables_apply(self) -> None:
        window = control_center.ControlCenterWindow.__new__(
            control_center.ControlCenterWindow
        )
        window.ollama_apply_button = Mock()
        state = OllamaPageState(7, (), (), error_code="control_stale")

        window.render_ollama(state)

        self.assertFalse(window.ollama_apply_sensitive())
        window.ollama_apply_button.set_sensitive.assert_called_with(False)

    def test_show_selects_ollama_page_before_refresh(self) -> None:
        window = control_center.ControlCenterWindow.__new__(
            control_center.ControlCenterWindow
        )
        window.window = Mock()
        window.notebook = Mock()
        window.refresh = Mock()

        window.show("ollama")

        window.notebook.set_current_page.assert_called_once_with(2)
        window.window.show_all.assert_called_once_with()
        window.refresh.assert_called_once_with()

    def test_ollama_refresh_loads_models_then_instances(self) -> None:
        window = control_center.ControlCenterWindow.__new__(
            control_center.ControlCenterWindow
        )
        window.controller = Mock()
        window.controller.submit.return_value = True
        window._set_busy = Mock()
        window.ollama_status_label = Mock()
        window.render_ollama = Mock()
        window._ollama_plan = {"plan_id": "stale"}
        models, instances = self._ollama_payloads()

        window.refresh_ollama()
        first_callback = window.controller.submit.call_args.args[2]
        first_callback(models)
        second_callback = window.controller.submit.call_args.args[2]
        second_callback(instances)

        self.assertEqual(
            [call.args[0] for call in window.controller.submit.call_args_list],
            ["fleet_ollama_models", "fleet_ollama_instances"],
        )
        state = window.render_ollama.call_args.args[0]
        self.assertEqual((state.generation, state.models[0].model_ref), (7, "model-a"))
        self.assertIsNone(window._ollama_plan)

    def test_ollama_refresh_fails_closed_on_invalid_payload(self) -> None:
        window = control_center.ControlCenterWindow.__new__(
            control_center.ControlCenterWindow
        )
        window._ollama_models_payload = {"models": []}
        window._set_busy = Mock()
        window.ollama_status_label = Mock()
        window.render_ollama = Mock()

        window._ollama_instances_loaded({"generation": "bad", "instances": []})

        state = window.render_ollama.call_args.args[0]
        self.assertEqual(state.error_code, "invalid_fleet_payload")

    def test_ollama_plan_builds_typed_request_and_enables_exact_apply(self) -> None:
        window = control_center.ControlCenterWindow.__new__(
            control_center.ControlCenterWindow
        )
        window.ollama_state = OllamaPageState(7, (), ())
        window.ollama_ref_entry = Mock(get_text=Mock(return_value="quiet-runner"))
        window.ollama_label_entry = Mock(get_text=Mock(return_value="Quiet Runner"))
        window.ollama_executable_entry = Mock(get_text=Mock(return_value="/usr/bin/ollama"))
        window.ollama_models_path_entry = Mock(get_text=Mock(return_value="/srv/ollama/models"))
        window.ollama_cpus_entry = Mock(get_text=Mock(return_value="4-7"))
        window.ollama_host_combo = Mock(get_active_id=Mock(return_value="control-host"))
        window.ollama_quota_spin = Mock(get_value_as_int=Mock(return_value=350))
        window.ollama_weight_spin = Mock(get_value_as_int=Mock(return_value=40))
        selected = Mock(get_active=Mock(return_value=True))
        window.ollama_model_checks = {"model-a": selected}
        window.controller = Mock()
        window.controller.submit.return_value = True
        window._set_busy = Mock()
        window.ollama_status_label = Mock()
        window.ollama_plan_view = Mock()
        window.ollama_apply_button = Mock()
        window._ollama_apply_enabled = False

        window._plan_ollama()
        callback = window.controller.submit.call_args.args[2]
        callback(
            {
                "plan_id": "plan-one",
                "plan_digest": "a" * 64,
                "expected_generation": 7,
            }
        )

        tool, arguments, _callback = window.controller.submit.call_args.args
        self.assertEqual(tool, "fleet_ollama_instance_plan")
        self.assertEqual(arguments["selected_model_refs"], ["model-a"])
        self.assertEqual(arguments["cpu_quota_percent"], 350)
        self.assertTrue(window.ollama_apply_sensitive())

    def test_ollama_apply_and_probe_use_generation_and_confirmation(self) -> None:
        window = control_center.ControlCenterWindow.__new__(
            control_center.ControlCenterWindow
        )
        window.ollama_state = OllamaPageState(7, (), ())
        window._ollama_plan = {"plan_id": "plan-one", "plan_digest": "a" * 64}
        window.ollama_ref_entry = Mock(get_text=Mock(return_value="quiet-runner"))
        window.controller = Mock()
        window.controller.submit.return_value = True
        window._confirm_message = Mock(return_value=True)
        window._set_busy = Mock()
        window.ollama_status_label = Mock()

        window._apply_ollama()
        apply = window.controller.submit.call_args
        window._probe_ollama()
        probe = window.controller.submit.call_args

        self.assertEqual(apply.args[0], "fleet_ollama_instance_apply")
        self.assertEqual(apply.args[1]["expected_generation"], 7)
        self.assertEqual(apply.args[1]["plan_digest"], "a" * 64)
        self.assertEqual(probe.args[0], "fleet_ollama_instance_probe")
        self.assertEqual(probe.args[1]["instance_ref"], "quiet-runner")
        self.assertEqual(probe.args[1]["expected_generation"], 7)

    def test_ollama_backend_errors_fail_closed_and_success_refreshes(self) -> None:
        window = control_center.ControlCenterWindow.__new__(
            control_center.ControlCenterWindow
        )
        window.render_ollama = Mock()
        window._set_busy = Mock()
        window.ollama_status_label = Mock()
        window.refresh_ollama = Mock()
        window._ollama_plan = {"plan_id": "plan-one"}

        window._ollama_models_loaded({"error": "denied"})
        window._ollama_mutation_finished("Prüfung", {"error": "not_ready"})
        window._ollama_mutation_finished("Prüfung", {"ready": True})

        failed_state = window.render_ollama.call_args.args[0]
        self.assertEqual(failed_state.error_code, "models_unavailable")
        self.assertIsNone(window._ollama_plan)
        window.refresh_ollama.assert_called_once_with()

    def test_action_block_reason_explains_safety_gate(self) -> None:
        clear = control_center.normalize_status_page(self._page(self._status_result())).rows[0]
        self.assertIsNone(control_center.action_block_reason(clear, "start"))
        self.assertEqual(control_center.action_block_reason(clear, "stop"), "Biene läuft nicht")
        self.assertIn("Letzter Auftrag: 2026-08-03T12:00:00+00:00", control_center.row_summary(clear))

        blocked = control_center.normalize_status_page(self._page(self._status_result(blocked=True))).rows[0]
        self.assertEqual(
            control_center.action_block_reason(blocked, "start"),
            "Geteilte Account-Reihe am Limit",
        )
        with self.assertRaisesRegex(ValueError, "unknown control-center action"):
            control_center.action_block_reason(clear, "delete")


class ControlCenterControllerTest(unittest.TestCase):
    def test_serializes_operations_and_refuses_close_while_busy(self) -> None:
        started = threading.Event()
        release = threading.Event()
        completed = threading.Event()
        results = []

        def dispatch(name, args):
            started.set()
            release.wait(2)
            return {"name": name, "args": args, "raw_output": "not_returned"}

        controller = control_center.OperationController(
            dispatch=dispatch,
            schedule=lambda callback, *args: (callback(*args), 1)[1],
        )
        self.assertTrue(controller.submit("agent_status", {"agent": "a1"}, lambda result: (results.append(result), completed.set())))
        self.assertTrue(started.wait(1))
        self.assertTrue(controller.busy)
        self.assertFalse(controller.submit("agent_stop", {"agent": "a1"}, lambda _result: None))

        release.set()
        self.assertTrue(completed.wait(2))
        self.assertEqual(results[0]["name"], "agent_status")
        self.assertFalse(controller.busy)
        self.assertTrue(controller.close())

    def test_redacts_dispatch_errors(self) -> None:
        completed = threading.Event()
        results = []

        def dispatch(_name, _args):
            raise AgentError("api_key=sk-super-secret-value")

        controller = control_center.OperationController(
            dispatch=dispatch,
            schedule=lambda callback, *args: (callback(*args), 1)[1],
        )
        self.assertTrue(controller.submit("agent_status", {}, lambda result: (results.append(result), completed.set())))
        self.assertTrue(completed.wait(2))
        self.assertNotIn("sk-super-secret-value", json.dumps(results))
        self.assertIn("error", results[0])
        self.assertTrue(controller.close())

    def test_tool_result_text_drops_private_fields_and_bounds_shape(self) -> None:
        text = control_center.bounded_public_result_text(
            {
                "ok": True,
                "token": "SECRET_TOKEN",
                "nested": {"backend_account_id": "PRIVATE_ACCOUNT", "status": "ready"},
                "many": list(range(500)),
            }
        )
        self.assertIn('"status": "ready"', text)
        self.assertNotIn("SECRET_TOKEN", text)
        self.assertNotIn("PRIVATE_ACCOUNT", text)
        self.assertLessEqual(len(text), control_center.MAX_RESULT_CHARS)

    def test_subprocess_dispatcher_decodes_one_bounded_rpc_response(self) -> None:
        child = (
            "import json,sys;"
            "request=json.loads(sys.stdin.readline());"
            "payload={'ok':True,'name':request['params']['name']};"
            "result={'content':[{'type':'text','text':json.dumps(payload)}],'isError':False};"
            "print(json.dumps({'jsonrpc':'2.0','id':1,'result':result}))"
        )
        dispatcher = control_center.SubprocessToolDispatcher(
            argv=[sys.executable, "-c", child],
            timeout_seconds=2,
        )
        self.assertEqual(dispatcher("agent_status", {}), {"ok": True, "name": "agent_status"})

    def test_subprocess_dispatcher_kills_hung_backend_at_deadline(self) -> None:
        dispatcher = control_center.SubprocessToolDispatcher(
            argv=[sys.executable, "-c", "import time; time.sleep(30)"],
            timeout_seconds=0.05,
        )
        started = time.monotonic()
        with self.assertRaisesRegex(AgentError, "outcome unknown after timeout"):
            dispatcher("agent_status", {})
        self.assertLess(time.monotonic() - started, 2)

    def test_subprocess_dispatcher_deadline_covers_blocked_request_write(self) -> None:
        dispatcher = control_center.SubprocessToolDispatcher(
            argv=[sys.executable, "-c", "import time; time.sleep(30)"],
            timeout_seconds=0.05,
        )
        started = time.monotonic()
        with self.assertRaisesRegex(AgentError, "outcome unknown after timeout"):
            dispatcher("agent_status", {"padding": "x" * 200_000})
        self.assertLess(time.monotonic() - started, 2)

    def test_subprocess_dispatcher_stops_reading_at_stream_cap(self) -> None:
        dispatcher = control_center.SubprocessToolDispatcher(
            argv=[
                sys.executable,
                "-c",
                f"import sys; sys.stdout.write('x' * {control_center.MAX_BACKEND_STDOUT_BYTES * 2})",
            ],
            timeout_seconds=2,
        )
        with self.assertRaisesRegex(AgentError, "output exceeded limit"):
            dispatcher("agent_status", {})

    def test_controller_forwards_cancel_to_killable_dispatcher(self) -> None:
        started = threading.Event()
        release = threading.Event()
        completed = threading.Event()

        class CancelDispatch:
            def prepare(self):
                return None

            def __call__(self, _name, _args):
                started.set()
                release.wait(2)
                return {"ok": True}

            def cancel(self):
                release.set()
                return True

        controller = control_center.OperationController(
            dispatch=CancelDispatch(),
            schedule=lambda callback, *args: (callback(*args), 1)[1],
        )
        self.assertTrue(controller.submit("agent_status", {}, lambda _result: completed.set()))
        self.assertTrue(started.wait(1))
        self.assertTrue(controller.cancel())
        self.assertTrue(completed.wait(2))
        self.assertTrue(controller.close())

    def test_controller_cancel_terminates_real_child_and_reports_unknown(self) -> None:
        completed = threading.Event()
        results = []
        dispatcher = control_center.SubprocessToolDispatcher(
            argv=[sys.executable, "-c", "import time; time.sleep(30)"],
            timeout_seconds=30,
        )
        controller = control_center.OperationController(
            dispatch=dispatcher,
            schedule=lambda callback, *args: (callback(*args), 1)[1],
        )
        self.assertTrue(controller.submit("agent_status", {}, lambda result: (results.append(result), completed.set())))
        deadline = time.monotonic() + 2
        while not controller.cancel() and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertTrue(completed.wait(2))
        self.assertIn("outcome unknown after cancellation", results[0]["error"])
        self.assertTrue(controller.close())

    def test_subprocess_dispatcher_honors_prepared_cancel_without_poisoning_idle(self) -> None:
        dispatcher = control_center.SubprocessToolDispatcher(
            argv=[sys.executable, "-c", "import time; time.sleep(30)"],
            timeout_seconds=30,
        )

        self.assertFalse(dispatcher.cancel())
        dispatcher.prepare()
        self.assertTrue(dispatcher.cancel())
        started = time.monotonic()
        with self.assertRaisesRegex(AgentError, "outcome unknown after cancellation"):
            dispatcher("agent_status", {})
        self.assertLess(time.monotonic() - started, 2)

    def test_close_state_suppresses_callback_and_followup_dispatch(self) -> None:
        started = threading.Event()
        release = threading.Event()
        callback_called = threading.Event()

        def dispatch(_name, _args):
            started.set()
            release.wait(2)
            return {"ok": True}

        controller = control_center.OperationController(
            dispatch=dispatch,
            schedule=lambda callback, *args: (callback(*args), 1)[1],
        )

        def callback(_result):
            callback_called.set()
            controller.submit("agent_stop", {"agent": "a1"}, lambda _next: None)

        self.assertTrue(controller.submit("agent_status", {}, callback))
        self.assertTrue(started.wait(1))
        self.assertFalse(controller.close())
        self.assertFalse(controller.submit("agent_stop", {"agent": "a1"}, lambda _result: None))
        release.set()
        deadline = time.monotonic() + 2
        while controller.busy and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertFalse(controller.busy)
        self.assertFalse(callback_called.is_set())
        self.assertTrue(controller.close())

    def test_scheduler_registration_failure_releases_controller(self) -> None:
        for schedule in (
            lambda _callback, *_args: 0,
            lambda _callback, *_args: (_ for _ in ()).throw(
                RuntimeError("injected scheduler failure")
            ),
        ):
            callback_called = threading.Event()
            controller = control_center.OperationController(
                dispatch=lambda _name, _args: {"ok": True},
                schedule=schedule,
            )

            self.assertTrue(
                controller.submit(
                    "agent_status", {}, lambda _result: callback_called.set()
                )
            )
            deadline = time.monotonic() + 2
            while controller.busy and time.monotonic() < deadline:
                time.sleep(0.01)

            self.assertFalse(controller.busy)
            self.assertFalse(callback_called.is_set())
            self.assertTrue(controller.close())

    def test_window_close_retries_cancel_then_destroys_after_backend_cleanup(self) -> None:
        class Controller:
            busy = True
            close_calls = 0
            cancel_calls = 0

            def close(self):
                self.close_calls += 1
                return self.close_calls > 1 and not self.busy

            def cancel(self):
                self.cancel_calls += 1
                return True

        callbacks = []
        view = control_center.ControlCenterWindow.__new__(control_center.ControlCenterWindow)
        view.controller = Controller()
        view.GLib = Mock()
        view.GLib.timeout_add.side_effect = lambda _delay, callback: callbacks.append(callback) or 7
        view.window = Mock()
        view.status_label = Mock()
        view.tool_status_label = Mock()
        view._close_poll_id = 0

        self.assertTrue(view._on_delete(None, None))
        self.assertEqual(view._close_poll_id, 7)
        self.assertEqual(view.controller.cancel_calls, 1)
        self.assertTrue(callbacks[0]())
        self.assertEqual(view.controller.cancel_calls, 2)
        view.controller.busy = False
        self.assertFalse(callbacks[0]())
        view.window.destroy.assert_called_once_with()

    def test_second_window_close_removes_pending_close_timer(self) -> None:
        controller = Mock()
        controller.close.side_effect = [False, True]
        controller.cancel.return_value = True
        view = control_center.ControlCenterWindow.__new__(control_center.ControlCenterWindow)
        view.controller = controller
        view.GLib = Mock()
        view.GLib.timeout_add.return_value = 9
        view.window = Mock()
        view.status_label = Mock()
        view.tool_status_label = Mock()
        view._close_poll_id = 0

        self.assertTrue(view._on_delete(None, None))
        self.assertFalse(view._on_delete(None, None))
        view.GLib.source_remove.assert_called_once_with(9)
        self.assertEqual(view._close_poll_id, 0)

    def test_window_close_does_not_wedge_when_close_timer_registration_fails(self) -> None:
        for failure in (0, RuntimeError("injected close timer failure")):
            controller = Mock()
            controller.close.return_value = False
            controller.cancel.return_value = True
            view = control_center.ControlCenterWindow.__new__(
                control_center.ControlCenterWindow
            )
            view.controller = controller
            view.GLib = Mock()
            if isinstance(failure, Exception):
                view.GLib.timeout_add.side_effect = failure
            else:
                view.GLib.timeout_add.return_value = failure
            view.window = Mock()
            view.status_label = Mock()
            view.tool_status_label = Mock()
            view._close_poll_id = 0

            self.assertFalse(view._on_delete(None, None))
            self.assertEqual(view._close_poll_id, 0)
            controller.cancel.assert_called_once_with()
            controller.abandon.assert_called_once_with()

    def test_invalid_close_timer_abandons_queued_delivery_and_executor(self) -> None:
        scheduled = []
        completed = threading.Event()

        def dispatch(_name, _args):
            completed.set()
            return {"ok": True}

        controller = control_center.OperationController(
            dispatch=dispatch,
            schedule=lambda callback, *args: scheduled.append((callback, args)) or 7,
        )
        self.assertTrue(controller.submit("agent_status", {}, lambda _result: None))
        self.assertTrue(completed.wait(1))
        deadline = time.monotonic() + 2
        while not scheduled and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertEqual(len(scheduled), 1)
        self.assertTrue(controller.busy)

        view = control_center.ControlCenterWindow.__new__(
            control_center.ControlCenterWindow
        )
        view.controller = controller
        view.GLib = Mock()
        view.GLib.timeout_add.return_value = 0
        view.window = Mock()
        view.status_label = Mock()
        view.tool_status_label = Mock()
        view._close_poll_id = 0

        self.assertFalse(view._on_delete(None, None))
        self.assertFalse(controller.busy)
        self.assertTrue(controller.close())
        self.assertTrue(controller._executor._shutdown)
        self.assertFalse(scheduled[0][0](*scheduled[0][1]))

    def test_optionless_tool_runs_when_user_selects_it(self) -> None:
        tool = control_center.ToolDescriptor(
            "agent_status", "Status", control_center.Risk.READ_ONLY, (), True, None
        )
        view = control_center.ControlCenterWindow.__new__(control_center.ControlCenterWindow)
        view.tool_selector = Mock()
        view.tool_selector.get_active_id.return_value = "0"
        view.visible_tools = (tool,)
        view._suppress_tool_auto_run = False
        view._render_tool_form = Mock()
        view._run_selected_tool = Mock()

        view._tool_selection_changed()

        view._render_tool_form.assert_called_once_with()
        view._run_selected_tool.assert_called_once_with()

    def test_tool_with_options_waits_for_execute_button(self) -> None:
        field = control_center.FieldDescriptor("agent", control_center.FieldKind.STRING, True)
        tool = control_center.ToolDescriptor(
            "agent_send", "Send", control_center.Risk.MUTATING, (field,), True, None
        )
        view = control_center.ControlCenterWindow.__new__(control_center.ControlCenterWindow)
        view.tool_selector = Mock()
        view.tool_selector.get_active_id.return_value = "0"
        view.visible_tools = (tool,)
        view._suppress_tool_auto_run = False
        view._render_tool_form = Mock()
        view._run_selected_tool = Mock()

        view._tool_selection_changed()

        view._render_tool_form.assert_called_once_with()
        view._run_selected_tool.assert_not_called()


class ControlCenterCliTest(unittest.TestCase):
    @patch("codex_master.control_center.launch_gtk_application", return_value=0)
    @patch("codex_master.control_center.require_teamleader_tool_access")
    @patch("codex_master.control_center.assert_install_context_allows_master_registration")
    def test_run_checks_main_context_and_role_then_launches(self, mock_context, mock_access, mock_launch) -> None:
        self.assertEqual(control_center.run_control_center([]), 0)
        mock_context.assert_called_once_with()
        mock_access.assert_called_once_with()
        mock_launch.assert_called_once_with([])

    @patch("codex_master.control_center.launch_gtk_application", return_value=0)
    @patch("codex_master.control_center.require_teamleader_tool_access")
    @patch("codex_master.control_center.assert_install_context_allows_master_registration")
    def test_run_accepts_only_ollama_deep_link(
        self, _mock_context, _mock_access, mock_launch
    ) -> None:
        self.assertEqual(
            control_center.run_control_center(["--page", "ollama"]), 0
        )
        mock_launch.assert_called_once_with(["--page", "ollama"])
        with self.assertRaisesRegex(AgentError, "page is invalid"):
            control_center.run_control_center(["--page", "secrets"])

    @patch("codex_master.control_center.load_gtk", side_effect=RuntimeError("GTK unavailable"))
    def test_launch_fails_without_traceback_when_gtk_is_missing(self, _mock_load) -> None:
        with self.assertRaisesRegex(AgentError, "GTK is unavailable"):
            control_center.launch_gtk_application([])

    @patch("codex_master.control_center.load_gtk")
    def test_launch_fails_closed_without_display(self, mock_load) -> None:
        fake_gtk = Mock()
        fake_gtk.init_check.return_value = (False, [])
        mock_load.return_value = (fake_gtk, Mock())

        with self.assertRaisesRegex(AgentError, "display is unavailable"):
            control_center.launch_gtk_application([])


if __name__ == "__main__":
    unittest.main()
