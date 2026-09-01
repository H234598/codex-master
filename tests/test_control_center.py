import json
import sys
import threading
import time
import unittest
from pathlib import Path
from types import ModuleType
from unittest.mock import Mock, patch

from codex_master import control_center
from codex_master.control_catalog import RISK_BY_TOOL
from codex_master.fleet_control import OllamaPageState
from codex_master.server import AgentError


def test_host_probe_page_button_runs_production_flow_and_refreshes_only_terminal() -> None:
    calls: list[tuple[str, dict]] = []
    events: list[str] = []
    delayed: list[tuple[object, tuple[object, ...]]] = []
    responses = [
        {"id": "op-success", "state": "planned"},
        {"id": "op-success", "state": "running"},
        {"id": "op-success", "state": "succeeded"},
        {"id": "op-failed", "state": "planned"},
        {"id": "op-failed", "state": "running"},
        {"id": "op-failed", "state": "failed"},
    ]

    class Controller:
        busy = False

        def submit(self, name, args, callback):
            calls.append((name, args))
            if name == "fleet_hosts":
                events.append("backend:host-refresh")
                callback(
                    {
                        "hosts": [
                            {
                                "schema_version": 1,
                                "ref": "worker-one",
                                "label": "Worker One",
                                "role": "execution",
                                "transport_binding": {
                                    "kind": "ssh",
                                    "binding_ref": "worker-one-ssh",
                                },
                                "capabilities": ["resource.probe"],
                                "reachability": {
                                    "state": "reachable",
                                    "latency_ms": 0,
                                },
                                "resource_evidence": {
                                    "cpu_threads": 8,
                                    "memory_bytes": 8 * 1024**3,
                                },
                                "generation": 5,
                                "observed_at": "2026-08-30T12:00:00Z",
                                "source": "host-agent",
                            }
                        ]
                    }
                )
                return True
            result = responses.pop(0)
            events.append(f"backend:{result['state']}")
            callback(result)
            return True

        def close(self):
            return True

    Gtk = ControlCenterWindowContractTest._mock_gtk()
    Gtk.Button.new_with_label.side_effect = lambda _label: Mock()
    Gtk.Entry.side_effect = lambda: Mock()
    Gtk.Label.side_effect = lambda **_values: Mock()
    Gtk.SpinButton.new_with_range.side_effect = lambda *_values: Mock()
    GLib = Mock()
    GLib.idle_add.return_value = 1

    def capture_timeout(_interval, callback, *args):  # type: ignore[no-untyped-def]
        delayed.append((callback, args))
        return len(delayed)

    GLib.timeout_add.side_effect = capture_timeout
    window = control_center.ControlCenterWindow(
        Gtk,
        GLib,
        object(),
        controller=Controller(),
    )
    window.host_ref_entry.get_text.return_value = "worker-one"
    window.host_generation_spin.get_value_as_int.return_value = 4
    window.list_box.get_children.return_value = []
    clicked = window.host_probe_button.connect.call_args.args[1]

    clicked(window.host_probe_button)
    assert [name for name, _args in calls] == ["fleet_host_probe"]
    callback, arguments = delayed.pop(0)
    callback(*arguments)
    assert [name for name, _args in calls] == [
        "fleet_host_probe",
        "fleet_operation_status",
    ]
    callback, arguments = delayed.pop(0)
    callback(*arguments)
    assert calls[-1][0] == "fleet_hosts"

    clicked(window.host_probe_button)
    callback, arguments = delayed.pop(0)
    callback(*arguments)
    callback, arguments = delayed.pop(0)
    callback(*arguments)

    assert [name for name, _args in calls] == [
        "fleet_host_probe",
        "fleet_operation_status",
        "fleet_operation_status",
        "fleet_hosts",
        "fleet_host_probe",
        "fleet_operation_status",
        "fleet_operation_status",
        "fleet_hosts",
    ]
    for index, (name, arguments) in enumerate(calls):
        if name == "fleet_host_probe":
            assert arguments["host_ref"] == "worker-one"
            assert arguments["expected_generation"] == 4
            assert arguments["idempotency_key"].startswith("gui-probe-")
            assert len(arguments["idempotency_key"]) <= 128
        elif name == "fleet_operation_status":
            assert arguments == {
                "operation_id": "op-success" if index < 4 else "op-failed"
            }
        else:
            assert arguments == {}
    rendered = [call.args[0] for call in window.host_probe_status_label.set_text.call_args_list]
    assert "Host-Probe: QUEUED" in rendered
    assert "Host-Probe: RUNNING" in rendered
    assert "Host-Probe: SUCCEEDED" in rendered
    assert "Host-Probe: UNKNOWN" in rendered
    assert events == [
        "backend:planned",
        "backend:running",
        "backend:succeeded",
        "backend:host-refresh",
        "backend:planned",
        "backend:running",
        "backend:failed",
        "backend:host-refresh",
    ]
    host_cards = [call.args[0] for call in window.host_card_label.set_text.call_args_list]
    assert any("Worker One" in value for value in host_cards)
    assert any("Generation 5" in value for value in host_cards)


def test_host_probe_submit_and_timer_scheduling_failures_are_visible() -> None:
    window = object.__new__(control_center.ControlCenterWindow)
    window._host_probe_operation_id = None
    window._host_probe_poll_attempts = 0
    window.host_ref_entry = Mock()
    window.host_ref_entry.get_text.return_value = "worker-one"
    window.host_generation_spin = Mock()
    window.host_generation_spin.get_value_as_int.return_value = 4
    window.host_probe_status_label = Mock()
    window.controller = Mock()
    window.controller.submit.side_effect = RuntimeError("submit unavailable")

    window._probe_selected_host()

    window.host_probe_status_label.set_text.assert_called_with(
        "Host-Probe: UNKNOWN"
    )

    window.controller = Mock()
    window.controller.submit.return_value = True
    window.GLib = Mock()
    window.GLib.timeout_add.return_value = 0
    window._host_probe_started({"id": "op-one", "state": "planned"})
    window.host_probe_status_label.set_text.assert_called_with(
        "Host-Probe: UNKNOWN"
    )


def test_delayed_host_probe_status_submit_exception_clears_poll_state() -> None:
    delayed: list[tuple[object, tuple[object, ...]]] = []
    window = object.__new__(control_center.ControlCenterWindow)
    window._host_probe_operation_id = None
    window._host_probe_poll_attempts = 0
    window.host_probe_status_label = Mock()
    window.refresh_host_card = Mock()
    window.controller = Mock()
    window.GLib = Mock()

    def capture(_interval, callback, *arguments):  # type: ignore[no-untyped-def]
        delayed.append((callback, arguments))
        return 1

    window.GLib.timeout_add.side_effect = capture
    window._host_probe_started({"id": "op-one", "state": "running"})
    callback, arguments = delayed.pop()
    window.controller.submit.side_effect = RuntimeError("submit unavailable")

    assert callback(*arguments) is False

    window.host_probe_status_label.set_text.assert_called_with(
        "Host-Probe: UNKNOWN"
    )
    assert window._host_probe_operation_id is None
    assert window._host_probe_poll_attempts == 0
    window.refresh_host_card.assert_not_called()


def test_host_probe_unknown_terminality_follows_canonical_operation_contract() -> None:
    noncanonical = control_center.host_probe_ui_state({"state": "unknown"})
    assert noncanonical == control_center.HostProbeUiState("UNKNOWN", False)
    for terminal in ("failed", "partial", "blocked"):
        assert control_center.host_probe_ui_state(
            {"state": terminal}
        ) == control_center.HostProbeUiState("UNKNOWN", True)

    window = object.__new__(control_center.ControlCenterWindow)
    window._host_probe_operation_id = "op-running"
    window._host_probe_poll_attempts = control_center.MAX_HOST_PROBE_POLLS
    window.host_probe_status_label = Mock()
    window.GLib = Mock()
    window.refresh_host_card = Mock()

    window._host_probe_started({"id": "op-running", "state": "running"})

    window.host_probe_status_label.set_text.assert_called_with(
        "Host-Probe: UNKNOWN"
    )
    window.GLib.timeout_add.assert_not_called()
    window.refresh_host_card.assert_not_called()


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

        window.notebook.set_current_page.assert_called_once_with(3)
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
    def test_backend_timeout_policy_and_prepared_abort_restore_idle_dispatcher(self) -> None:
        self.assertEqual(
            control_center.backend_timeout_seconds(
                "agent_wait", {"timeout_seconds": 300}
            ),
            330,
        )
        self.assertEqual(
            control_center.backend_timeout_seconds("agent_pool_install", {}), 600
        )
        self.assertEqual(
            control_center.backend_timeout_seconds("agent_status", {}),
            control_center.DEFAULT_BACKEND_TIMEOUT_SECONDS,
        )

        dispatcher = control_center.SubprocessToolDispatcher(
            argv=[sys.executable, "-c", "pass"]
        )
        dispatcher.prepare()
        dispatcher.abort_prepare()
        dispatcher.prepare()
        dispatcher.abort_prepare()

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

    def test_subprocess_dispatcher_defaults_to_the_runtime_image_entrypoint(self) -> None:
        entrypoint = Path("/tmp/codex-master-runtime/bin/codex-master-mcp")

        with patch.object(control_center, "runtime_mcp_entrypoint", return_value=entrypoint):
            dispatcher = control_center.SubprocessToolDispatcher()

        self.assertEqual(dispatcher._argv, [str(entrypoint)])

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

    def test_scheduler_registration_failure_reports_visible_unknown_result(self) -> None:
        for schedule in (
            lambda _callback, *_args: 0,
            lambda _callback, *_args: (_ for _ in ()).throw(
                RuntimeError("injected scheduler failure")
            ),
        ):
            callback_called = threading.Event()
            results = []
            controller = control_center.OperationController(
                dispatch=lambda _name, _args: {"ok": True},
                schedule=schedule,
            )

            self.assertTrue(
                controller.submit(
                    "agent_status",
                    {},
                    lambda result: (results.append(result), callback_called.set()),
                )
            )

            self.assertTrue(callback_called.wait(2))
            self.assertFalse(controller.busy)
            self.assertEqual(results, [{"error": "control-center delivery unavailable"}])
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


class ControlCenterWindowContractTest(unittest.TestCase):
    @staticmethod
    def _mock_gtk() -> Mock:
        Gtk = Mock()
        Gtk.ComboBoxText.return_value.get_active_text.return_value = "Alle"
        Gtk.ResponseType.OK = "ok"
        Gtk.ResponseType.CANCEL = "cancel"
        Gtk.MessageDialog.return_value.run.return_value = "ok"
        Gtk.Dialog.return_value.run.return_value = "ok"
        return Gtk

    def test_constructor_builds_all_pages_without_real_display(self) -> None:
        Gtk = self._mock_gtk()
        GLib = Mock()
        GLib.idle_add.return_value = 1

        controller = Mock()
        controller.close.return_value = True
        window = control_center.ControlCenterWindow(
            Gtk, GLib, object(), controller=controller
        )
        try:
            self.assertEqual(
                window.page_names(),
                {
                    "Übersicht",
                    "Hosts",
                    "Werkzeuge",
                    "Ollama/Modelle",
                    "Ollama/Instanzen",
                },
            )
            self.assertIs(window.Gtk, Gtk)
            self.assertGreater(len(window.tool_catalog), 0)
            self.assertEqual(Gtk.Notebook.return_value.append_page.call_count, 6)
        finally:
            self.assertTrue(window.controller.close())

    def test_tool_form_renders_reads_and_bounds_public_result(self) -> None:
        Gtk = self._mock_gtk()
        entry = Mock(spec=["get_text", "set_max_length", "set_text"])
        entry.get_text.return_value = "a1"
        Gtk.Entry.return_value = entry
        view = control_center.ControlCenterWindow.__new__(
            control_center.ControlCenterWindow
        )
        view.Gtk = Gtk
        view.tool_form = Mock()
        view.tool_form.get_children.return_value = [Mock()]
        view.tool_inputs = {"old": (Mock(), Mock(), Mock(), "text")}
        view.tool_description_label = Mock()
        view.tool_risk_label = Mock()
        view.tool_run_button = Mock()
        view.controller = Mock(busy=False)
        field = control_center.FieldDescriptor(
            "agent",
            control_center.FieldKind.STRING,
            True,
            description="Konkrete Biene",
        )
        tool = control_center.ToolDescriptor(
            "agent_status",
            "Status laden",
            control_center.Risk.READ_ONLY,
            (field,),
            True,
        )
        view.selected_tool = tool

        view._render_tool_form()

        self.assertEqual(view._read_tool_arguments(tool), {"agent": "a1"})
        self.assertEqual(set(view.tool_inputs), {"agent"})
        view.tool_result = Mock()
        view._set_tool_result({"ok": True, "token": "not-public"})
        rendered = view.tool_result.get_buffer.return_value.set_text.call_args.args[0]
        self.assertIn('"ok": true', rendered)
        self.assertNotIn("not-public", rendered)

    def test_confirmation_contracts_cover_each_risk_class(self) -> None:
        Gtk = self._mock_gtk()
        view = control_center.ControlCenterWindow.__new__(
            control_center.ControlCenterWindow
        )
        view.Gtk = Gtk
        view.window = Mock()
        tool = control_center.ToolDescriptor(
            "agent_pool_destroy_pool",
            "Pool löschen",
            control_center.Risk.DESTRUCTIVE,
            (),
            True,
        )
        phrase = f"AUSFÜHREN {tool.name}"
        Gtk.Entry.return_value.get_text.return_value = phrase

        self.assertTrue(view._confirm_message("Fortfahren?"))
        self.assertTrue(view._confirm_destructive(tool))
        self.assertTrue(
            view._confirm_tool_run(tool, control_center.Risk.READ_ONLY, 0)
        )
        with patch.object(view, "_confirm_message", return_value=True) as confirm:
            self.assertTrue(
                view._confirm_tool_run(tool, control_center.Risk.BROAD, 2)
            )
            self.assertEqual(confirm.call_count, 2)

    def test_tool_run_preview_and_completion_follow_risk_contract(self) -> None:
        view = control_center.ControlCenterWindow.__new__(
            control_center.ControlCenterWindow
        )
        tool = control_center.ToolDescriptor(
            "agent_pool_destroy_pool",
            "Pool löschen",
            control_center.Risk.DESTRUCTIVE,
            (),
            True,
        )
        view.selected_tool = tool
        view._read_tool_arguments = Mock(
            return_value={"spec": "a-series", "allow_destructive": True}
        )
        view._confirm_message = Mock(return_value=True)
        view._confirm_destructive = Mock(return_value=True)
        view._confirm_tool_run = Mock(return_value=True)
        view._set_busy = Mock()
        view._set_tool_result = Mock()
        view.tool_status_label = Mock()
        view.controller = Mock()
        view.controller.submit.return_value = True
        view.refresh = Mock()

        view._run_selected_tool()
        preview_callback = view.controller.submit.call_args.args[2]
        self.assertEqual(view.controller.submit.call_args.args[0], "agent_pool_status")
        preview_callback({"ok": True})
        destroy_callback = view.controller.submit.call_args.args[2]
        self.assertEqual(
            view.controller.submit.call_args.args[0], "agent_pool_destroy_pool"
        )
        destroy_callback({"ok": True})

        view._set_tool_result.assert_called_with({"ok": True})
        view.refresh.assert_called_once_with()

    def test_status_navigation_render_and_mutation_use_bounded_contracts(self) -> None:
        Gtk = self._mock_gtk()
        view = control_center.ControlCenterWindow.__new__(
            control_center.ControlCenterWindow
        )
        view.Gtk = Gtk
        view.page = 2
        view.last_page = None
        view.search = Mock()
        view.search.get_text.return_value = "a"
        view.refresh_button = Mock()
        view.previous_button = Mock()
        view.next_button = Mock()
        view.status_label = Mock()
        view.list_box = Mock()
        view.list_box.get_children.return_value = [Mock()]
        view.window = Mock()
        view.controller = Mock()
        view.controller.busy = False
        view.controller.submit.return_value = True
        view.selected_tool = None

        self.assertEqual(view._filter_text(), "a")
        view.refresh()
        self.assertEqual(
            view.controller.submit.call_args.args[:2],
            (
                "agent_status",
                {"agent": "a-series", "agents_offset": 40, "agents_limit": 20},
            ),
        )
        view._apply_filter()
        self.assertEqual(view.page, 0)
        view._change_page(1)
        self.assertEqual(view.page, 1)

        payload = ControlCenterViewModelTest()._page(
            ControlCenterViewModelTest()._status_result()
        )
        view._status_loaded(payload)
        self.assertEqual(view.last_page.total_count, 300)
        self.assertEqual(view.list_box.add.call_count, 1)

        view._confirm_mutation("start", "a1")
        self.assertEqual(view.controller.submit.call_args.args[0], "agent_start")
        self.assertEqual(view.controller.submit.call_args.args[1]["agent"], "a1")
        view._mutation_finished("stop", "a1", {"ok": True})
        self.assertEqual(view.controller.submit.call_args.args[0], "agent_status")


class ControlCenterGtkBoundaryTest(unittest.TestCase):
    def test_load_gtk_returns_imported_repository_modules(self) -> None:
        gi = ModuleType("gi")
        gi.require_version = Mock()
        repository = ModuleType("gi.repository")
        repository.Gtk = object()
        repository.GLib = object()
        gi.repository = repository

        with patch.dict(
            sys.modules,
            {"gi": gi, "gi.repository": repository},
        ):
            Gtk, GLib = control_center.load_gtk()

        gi.require_version.assert_called_once_with("Gtk", "3.0")
        self.assertIs(Gtk, repository.Gtk)
        self.assertIs(GLib, repository.GLib)

    @patch("codex_master.control_center.load_gtk")
    def test_launch_activation_reuses_one_window_and_honors_deep_link(
        self, mock_load
    ) -> None:
        Gtk = Mock()
        Gtk.init_check.return_value = (True, [])
        application = Mock()
        activate = None

        def connect(signal, callback):
            nonlocal activate
            self.assertEqual(signal, "activate")
            activate = callback

        def run(_args):
            assert activate is not None
            activate(application)
            activate(application)
            return 23

        application.connect.side_effect = connect
        application.run.side_effect = run
        Gtk.Application.return_value = application
        mock_load.return_value = (Gtk, Mock())
        window = Mock()

        with patch(
            "codex_master.control_center.ControlCenterWindow",
            return_value=window,
        ) as window_class:
            self.assertEqual(
                control_center.launch_gtk_application(["--page", "ollama"]), 23
            )

        window_class.assert_called_once_with(Gtk, mock_load.return_value[1], application)
        self.assertEqual(window.show.call_args_list[0].args, ("ollama",))
        self.assertEqual(window.show.call_count, 2)


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
