import json
import sys
import threading
import time
import unittest
from unittest.mock import Mock, patch

from codex_master import control_center
from codex_master.control_catalog import RISK_BY_TOOL
from codex_master.server import AgentError


class ControlCenterViewModelTest(unittest.TestCase):
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
            schedule=lambda callback, *args: callback(*args),
        )
        self.assertTrue(controller.submit("agent_status", {"agent": "a1"}, lambda result: (results.append(result), completed.set())))
        self.assertTrue(started.wait(1))
        self.assertTrue(controller.busy)
        self.assertFalse(controller.submit("agent_stop", {"agent": "a1"}, lambda _result: None))
        self.assertFalse(controller.close())

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
            schedule=lambda callback, *args: callback(*args),
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
        class CancelDispatch:
            def __call__(self, _name, _args):
                return {"ok": True}

            def cancel(self):
                return True

        controller = control_center.OperationController(
            dispatch=CancelDispatch(),
            schedule=lambda callback, *args: callback(*args),
        )
        self.assertTrue(controller.cancel())
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
            schedule=lambda callback, *args: callback(*args),
        )
        self.assertTrue(controller.submit("agent_status", {}, lambda result: (results.append(result), completed.set())))
        deadline = time.monotonic() + 2
        while not controller.cancel() and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertTrue(completed.wait(2))
        self.assertIn("outcome unknown after cancellation", results[0]["error"])
        self.assertTrue(controller.close())


class ControlCenterCliTest(unittest.TestCase):
    @patch("codex_master.control_center.launch_gtk_application", return_value=0)
    @patch("codex_master.control_center.require_teamleader_tool_access")
    @patch("codex_master.control_center.assert_install_context_allows_master_registration")
    def test_run_checks_main_context_and_role_then_launches(self, mock_context, mock_access, mock_launch) -> None:
        self.assertEqual(control_center.run_control_center([]), 0)
        mock_context.assert_called_once_with()
        mock_access.assert_called_once_with()
        mock_launch.assert_called_once_with([])

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
