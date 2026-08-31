# Task 6 report: active local and remote host probes

## Root cause and architecture

The durable host-agent queue already constrained remote work to the fixed
`host.probe/collect` action, but there was no public probe DTO, no bounded
local collector, and no admin operation to initiate it. This task adds a
privacy-preserving `HostProbeEvidenceV1` with a canonical digest and bounded
classes only. It never exposes hostname, address, MAC, paths, mounts,
processes, commands, URLs, or argv.

`LocalHostProbeAdapter` creates and completes an existing `AdminOperationStore`
operation after a direct bounded collection and records only compatible
registry resource fields. `RemoteHostProbeAdapter` creates the same admin
operation and enqueues only `host.probe/collect` in the existing
`AgentOperationStore`; it contains no shell or arbitrary remote arguments.
`HostProbeRouter` selects the known control host for direct collection and
keeps other hosts asynchronous.

The admin contract adds `hosts.probe` with scope `fleet.host.probe`, generation
checking, and idempotency. The HTTPS route is exactly
`POST /admin/v1/hosts/{ref}/probe` and requires the TOTP step-up header. The
Unix socket still relies on its principal scope and does not require TOTP.
CLI and MCP share the existing admin catalog: `fleet host probe HOST_REF
--expected-generation N --json` and `fleet_host_probe`.

## RED evidence

Before implementation:

```text
PYTHONPATH=src pytest -q tests/test_host_probe.py
ModuleNotFoundError: No module named 'codex_master.host_probe'
```

## Changes

- Added bounded DTO/collector and local/remote adapters in `host_probe.py`.
- Added `hosts.probe` metadata, service dispatch, generation owner check, and
  HTTPS route step-up enforcement.
- Wired production assembly to the existing admin and agent operation stores.
- Added CLI/MCP catalog entries and a positional host-ref CLI form.
- Added DTO boundary and contract metadata tests.

## Validation

```text
PYTHONPATH=src pytest -q tests/test_host_probe.py tests/test_admin_contracts.py tests/test_admin_http.py tests/test_admin_service.py tests/test_admin_cli_mcp_integration.py -k 'host or probe'
10 passed, 244 deselected in 3.63s

ruff check src/codex_master/host_probe.py src/codex_master/admin_contracts.py src/codex_master/admin_http.py src/codex_master/admin_service.py src/codex_master/admin_assembly.py src/codex_master/control_catalog.py src/codex_master/control_center.py tests/test_host_probe.py
All checks passed!

git diff --check
(clean)
```

## Self-review and CodeRabbit

Secret preflight found no private-key or token pattern in the task diff.
CodeRabbit 0.7.5 was authenticated and invoked as
`coderabbit review --agent -t uncommitted`; it reached its analysis setup but
did not return findings before the command-runner time limit. No review finding
was available to apply. Manual review confirmed the fixed allow-list remote
action, no shell/URL/argv inputs, and no private host fields in public DTOs.

## Scope and risks

Only Task-6 files were edited. An unrelated pre-existing modification to
`progress.md` was preserved and is not staged. The agent receipt completion
hook is owned by the pre-existing agent daemon and is intentionally not changed
in this task's permitted file set; remote collection is queued asynchronously,
but recording a receipt into the registry requires that existing owner hook to
call the adapter completion path. This is the remaining integration risk.

## Fix round 1/5

The agent-operation record now has an optional, persisted `target_host_ref`.
The poll path skips a target-bound operation for every other principal, while
the existing receipt lease fence continues to reject a cross-host completion.
This is the sole supporting-owner extension; it is private, bounded, and adds
no public result wire.

`RemoteHostProbeCompletionOwner` is installed on the host-agent HTTP receipt
path. It validates the fixed action, exact target, generation, canonical
`HostProbeEvidenceV1` public DTO and digest before recording a probe. Invalid,
stale, cross-host and unknown outcomes do not mutate the registry. Both probe
adapters now derive a bounded host-bound internal operation key. The CLI keeps
the required `--json` switch and derives its stable key from host and
generation, so it no longer asks the operator for `--idempotency-key`.

RED:

```text
PYTHONPATH=src pytest -q tests/test_agent_operations.py -k target_host_fence
FAILED: AgentOperationRequestV1.__init__() got an unexpected keyword argument 'target_host_ref'
```

GREEN:

```text
PYTHONPATH=src pytest -q tests/test_host_probe.py tests/test_admin_contracts.py tests/test_admin_http.py tests/test_admin_service.py tests/test_admin_cli_mcp_integration.py tests/test_agent_operations.py tests/test_control_catalog.py tests/test_control_center.py -k 'host or probe'
19 passed, 316 deselected in 5.34s

ruff check <changed Task-6 modules and focused tests>
All checks passed!

python -m compileall -q <changed production modules>
(clean)

git diff --check
(clean)
```

The fix also adds the mutating catalog entry and a headless Control Center
state contract: `QUEUED`, `RUNNING`, `SUCCEEDED`, `UNKNOWN`; host-card refresh
is allowed only for terminal states.

## Fix round 2/5

RED evidence:

```text
PYTHONPATH=src pytest -q tests/test_host_probe.py -k noncanonical
2 failed, 1 passed: malformed and impossible observed_at values were accepted.
```

GREEN evidence:

```text
PYTHONPATH=src pytest -q tests/test_host_probe.py tests/test_agent_operations.py tests/test_agent_http.py tests/test_agent_daemon.py tests/test_admin_http.py tests/test_admin_service.py tests/test_admin_cli_mcp_integration.py tests/test_control_catalog.py tests/test_control_center.py -k 'host or probe or assemble_server or completion_owner'
26 passed, 274 deselected in 6.17s

ruff check <all changed Task-6 production modules and direct tests>
All checks passed!

python -m compileall -q <changed production modules>
(clean)

git diff --check
(clean)
```

`HostProbeEvidenceV1` now parses and exact-round-trips canonical UTC seconds.
The registry gained the narrow `record_active_probe()` API: adapters submit
only fresh resource evidence and observation time; registration and binding
metadata are read and preserved inside the registry owner.

Completion ordering is explicitly recoverable rather than claimed atomic:
all receipt fences and DTO validation happen before mutation; the admin
operation becomes running before the registry write; registry is then written,
admin is terminalized, and finally the agent receipt is terminalized. A retry
of the same agent receipt after a completed admin operation only terminalizes
the agent operation and does not write the registry again. The daemon assembly
accepts a test state root and catches `AdminOperationError` at its stable
startup boundary.

## Fix round 3/5

The active-probe registry path is now one lock-held transaction. It derives its
active observation digest from ref, generation, fresh resources, reachability
and observed time only; registration/binding metadata stays internal to the
registry owner. Identical generation retries return the existing observation.

Completion accepts planned or already-running admin work, allowing recovery
after a successful registry write followed by an interrupted admin step or
finish. A terminal admin retry only completes the pending agent receipt and
does not write the registry again. The host page now starts `fleet_host_probe`,
polls `fleet_operation_status`, renders the probe state and refreshes only once
the operation is terminal. The daemon startup boundary additionally handles
`AgentOperationError`.

```text
PYTHONPATH=src pytest -q tests/test_host_probe.py tests/test_admin_hosts.py tests/test_agent_operations.py tests/test_agent_http.py tests/test_agent_daemon.py tests/test_admin_contracts.py tests/test_admin_http.py tests/test_admin_service.py tests/test_admin_cli_mcp_integration.py tests/test_control_catalog.py tests/test_control_center.py -k 'host or probe or assemble_server or startup'
154 passed, 354 deselected in 4.28s
```

## Fix round 4/5

Executable RED coverage was added before production edits for the real local
and remote adapters, the completion owner and all three durable stores, the
real CLI/MCP subprocess paths, the constructed GTK host action, active-probe
metadata/CAS behavior, and daemon startup assembly failures.

RED:

```text
PYTHONPATH=src pytest -q tests/test_host_probe.py tests/test_admin_hosts.py \
  tests/test_admin_cli_mcp_integration.py tests/test_control_center.py \
  tests/test_agent_daemon.py -k 'host or probe or assemble_server or startup'

17 failed, 147 passed, 78 deselected in 8.50s

Representative exact failures:
- LocalHostProbeAdapter returned `failed` instead of `succeeded` because the
  fresh observation reused generation 4 instead of advancing to generation 5.
- Valid remote completion returned a running Admin operation while the Agent
  operation was already succeeded.
- Injected Admin begin/record_step/finish failures on non-success completion
  did not raise and could not resume the running operation on retry.
- Injected Registry/Admin failures on success were swallowed instead of
  leaving retryable durable state.
- The real host CLI did not bind the Admin socket path.
- ControlCenterWindow rejected the production controller seam and had no host
  page button construction path.
```

The aggregate also caught a test-harness `FileExistsError` from constructing
the same subprocess environment twice; the harness was corrected before the
isolated CLI baseline was evaluated.

After correcting the CLI test's one-time environment construction, the
isolated baseline CLI RED was:

```text
PYTHONPATH=src pytest -q \
  tests/test_admin_cli_mcp_integration.py::test_real_host_probe_cli_uses_exact_parser_contract_and_internal_key
FAILED: expected returncode 0, got 1 with
{"error": "control.service_unavailable"}
1 failed in 2.75s
```

Recovery implementation:

- `AgentOperationStore.validate_completion()` now validates all receipt and
  lease fences without mutation and returns only the fixed private owner
  context. `RemoteHostProbeCompletionOwner` validates that context, exact host,
  exact expected generation and Admin plan before any transition.
- Success and failure paths now share explicit `planned`/`running`/terminal
  recovery. The Admin operation becomes terminal before the Agent receipt is
  completed. Registry, begin, step, finish, and Agent-complete interruption
  tests all converge on retry; Registry writes remain single-mutation.
- Fresh active observations advance from expected generation N to N+1.
  Planned stale results fail without Registry mutation; a running retry accepts
  N+1 only when the active observation is idempotently identical.
- Invalid DTO, stale, cross-host, failed, and unknown cases retain byte-exact
  Registry state. Duplicate identical terminal receipts remain idempotent and
  conflicting receipts remain rejected.
- The exact host CLI now connects to the attested Admin socket. Real subprocess
  CLI/MCP tests prove exact forwarding, bounded stable internal CLI key,
  caller-owned MCP key, operation projection, and absence of a public CLI
  `--idempotency-key` option.
- The production GTK window now constructs a Hosts page/card/button signal,
  renders QUEUED/RUNNING/SUCCEEDED/UNKNOWN, polls with a bounded delayed
  `GLib.timeout_add` path, and refreshes only after canonical terminal states.
- Active-probe tests prove metadata/private-binding preservation,
  metadata-independent digesting, same-generation conflict rejection, and a
  deterministic lock-seam interleaving that preserves a concurrent CAS update.
- Daemon tests inject each production Host Registry, Agent operation, and Admin
  operation constructor failure and prove the same unavailable exit/message
  without traceback while preserving the injectable `state_root` assembly.

GREEN:

```text
PYTHONPATH=src pytest -q tests/test_host_probe.py tests/test_admin_hosts.py \
  tests/test_agent_operations.py tests/test_agent_http.py \
  tests/test_agent_daemon.py tests/test_admin_contracts.py \
  tests/test_admin_http.py tests/test_admin_service.py \
  tests/test_admin_cli_mcp_integration.py tests/test_control_catalog.py \
  tests/test_control_center.py \
  -k 'host or probe or assemble_server or startup'
183 passed, 355 deselected in 5.95s

PYTHONPATH=src pytest -q tests/test_host_probe.py tests/test_admin_hosts.py \
  tests/test_agent_daemon.py tests/test_admin_cli_mcp_integration.py \
  tests/test_control_center.py
243 passed, 5 subtests passed in 12.79s

PYTHONPATH=src pytest -q tests/test_agent_operations.py
22 passed in 80.93s

ruff check <all changed Python files>
All checks passed!

python -m compileall -q <all changed production modules>
(clean)

git diff --check
(clean)
```

Secret preflight of the exact Task-6 diff found no private-key, cloud-key,
GitHub-token, OpenAI-key, Google-key, or JWT credential pattern. CodeRabbit
0.7.5 first reported one valid major concern about immediate unbounded Control
Center polling; bounded delayed polling and its executable test were added.
The independent follow-up review completed with zero findings.
