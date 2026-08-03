# Task 3 report — Vertrag 2 und automatische tmux-Inventur

Date: 2026-08-03
Worktree: `/home/teladi/.codex-worktrees/codex-master/flottenmanagement_readonly`
Scope: `src/codex_master/server.py`, `tests/test_server.py`

## Ergebnis

Implemented contract v2 for applet status with bounded one-shot tmux inventory, `schema_version` routing, `known_running` fast-path, CLI `--schema-version`, and validation updates. Contract v1 path stays separate and unchanged by default.

## RED

Command:

```bash
PYTHONPATH=src python3 -m unittest tests.test_server.AppletStatusContractTest tests.test_server.CliLifecycleTest -v
```

Observed failures before implementation:

- `test_applet_agent_observation_known_running_true_skips_has_session` → `ERROR`
- `test_applet_status_rejects_invalid_schema_versions` → `ERROR`
- `test_applet_status_schema_v1_rejects_empty_agents` → `ERROR`
- `test_applet_status_schema_v2_accepts_empty_inventory_and_keeps_pinned_sleepers` → `ERROR`
- `test_applet_status_schema_v2_inventory_error_has_no_fallback_rows` → `ERROR`
- `test_applet_status_schema_v2_limits_visible_rows_and_reports_active_overflow` → `ERROR`
- `test_applet_status_schema_v2_lists_managed_inventory_once_and_pins_sleepers` → `ERROR`
- `test_applet_status_schema_v2_native_bridge_degradation_keeps_managed_rows` → `ERROR`
- `test_cli_applet_status_routes_to_master_applet_tool` → `FAIL`
- `test_cli_applet_status_schema_v2_allows_empty_agents` → argparse `unrecognized arguments: --schema-version`
- `test_cli_applet_status_without_schema_version_and_agents_fails_closed` → argparse required `agents`

Root cause from red run: no `schema_version` support, no bounded list-sessions inventory path, no `known_running` parameter, old CLI shape, old tool wiring.

## GREEN

Focused command:

```bash
PYTHONPATH=src python3 -m unittest tests.test_server.AppletStatusContractTest tests.test_server.CliLifecycleTest -v
```

Result:

```text
Ran 109 tests in 59.964s
OK
```

Full suite first rerun found one compatibility miss:

- `test_call_tool_delegates_to_master_applet_status` expected old `applet_status(["a1", "b1"])` call signature

Patched test expectation, then reran:

```bash
PYTHONPATH=src python3 -m unittest tests.test_server.ServerHelpersTest.test_call_tool_delegates_to_master_applet_status -v
PYTHONPATH=src python3 -m unittest discover -s tests -q
```

Final verification:

```text
Ran 1 test in 0.003s
OK

Ran 782 tests in 107.974s
OK
```

## Self-review

- Timeout calls: v2 inventory uses exactly `run_tmux(["list-sessions", "-F", "#{session_name}"], check=False, timeout=1.0)`.
- Empty-list aggregates: `applet_status([], schema_version=1)` fails closed; `applet_status([], schema_version=2)` succeeds.
- Privacy: inventory/native failures return degraded or empty public payloads only; no raw tmux stderr exposed.
- One-inventory invariant: v2 does one `list-sessions`; visible managed rows pass `known_running` and skip per-agent `has-session`.
- Compatibility: v1 remains default path; MCP `agents` still required; bounds now `0..6`; `schema_version` integer enum `[1, 2]`.

## Files changed

- `src/codex_master/server.py`
- `tests/test_server.py`

## Commit

Planned message:

```text
feat: add automatic applet status contract v2
```
