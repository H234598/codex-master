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

## Fix round 5/5

Round 5 closes all findings from `task-6-rereview-4.md` without adding a
generic Task-7 result projection or broadening the host-agent action surface.

### RED evidence

The first focused round-5 command intentionally combined the new regressions
before production edits:

```text
PYTHONPATH=src pytest -q tests/test_host_probe.py \
  tests/test_admin_operations.py::test_only_restart_reconciled_host_probe_can_be_resumed \
  tests/test_admin_hosts.py::test_active_probe_owns_one_lock_and_rejects_contending_stale_cas \
  tests/test_control_center.py::test_host_probe_page_button_runs_production_flow_and_refreshes_only_terminal \
  tests/test_control_center.py::test_host_probe_submit_and_timer_scheduling_failures_are_visible \
  tests/test_control_center.py::ControlCenterViewModelTest::test_show_selects_ollama_page_before_refresh \
  tests/test_control_center.py::ControlCenterControllerTest::test_scheduler_registration_failure_reports_visible_unknown_result \
  tests/test_admin_cli_mcp_integration.py::test_real_host_probe_cli_uses_exact_parser_contract_and_internal_key \
  tests/test_admin_cli_mcp_integration.py::test_real_registered_host_probe_mcp_call_forwards_caller_key \
  tests/test_control_catalog.py::ControlCatalogTest::test_risk_registry_exactly_covers_current_tools

45 failed, 13 passed in 16.35s
```

Representative failures were the missing document-generation dependency on
`RemoteHostProbeAdapter`, missing host-probe resume API, GTK terminal refresh
still dispatching `agent_status`, submit exceptions escaping the UI, silent
scheduler registration failure, Ollama still selecting notebook index 2,
`--json` omission executing a real probe instead of exiting 2, and the absent
read-only Hosts tool.

The replacement event-controlled concurrency test passed during RED. That is
expected evidence: production already used one lock-held transaction; the old
test was the defect because its alleged concurrent update finished before the
probe lock was acquired.

CodeRabbit's first review found that the new reclaim transition could bypass
the original plan expiry. A dedicated regression was added before its fix:

```text
PYTHONPATH=src pytest -q \
  tests/test_admin_operations.py::test_expired_restart_reconciled_host_probe_cannot_be_resumed

1 failed: DID NOT RAISE AdminOperationError
```

### Durable and contract decisions

- `HostRegistry.document_generation()` exposes only the authoritative integer
  document generation. Remote Agent queue/principal fences use this value;
  the Admin operation remains the separate durable owner of the per-host
  expected generation.
- The private Agent lease arguments remain exactly
  `{"admin_operation_id": ..., "probe_schema": 1}`. Kind/action remain exactly
  `host.probe/collect`, and `target_host_ref` remains the separate target fence.
- Registry `get()` translates only definitive `control.host_not_found` or
  `host.identity_not_found`. Store availability/corruption errors propagate
  with Admin and Agent state unchanged so the identical receipt can retry.
- `AdminOperationStore.resume_host_probe()` accepts only
  `hosts.probe`, the exact `host.probe.collect` step, matching generation,
  `partial` with exactly `control.restart_reconciled`, no owner, and an
  unexpired plan. Every other operation and ordinary partial state retains the
  existing contract.
- Completion reloads/reclaims Admin state before each post-restart mutation.
  Tests reconstruct Admin store, Agent store, Registry, and completion owner,
  crash after each durable completion boundary (including reclaim itself),
  and prove Admin terminal state exists before Agent terminalization.
- Host generation exhaustion and Registry document-generation exhaustion map
  to a bounded Admin failure; the receipt is terminalized only after Admin,
  with no Registry mutation or permanent running/leased state.
- The GTK Hosts page now has an explicit public Hosts-list load, renders the
  selected HostRegistry record, captures delayed GLib poll callbacks in tests,
  and refreshes that data only at canonical terminal states. Submit, poll
  scheduling, host refresh, and controller delivery scheduling failures render
  `Host-Probe: UNKNOWN`. `--page ollama` selects index 3.
- CLI parsing requires the literal `--json` switch. Omission is proven by a
  real subprocess to exit with argparse status 2. The CLI still has no public
  idempotency option; MCP still forwards its caller-provided key exactly.
- The old interleaving seam was replaced by two real threads and bounded
  events. The contender reaches the production state-lock acquisition while
  the probe owns it, cannot acquire early, then observes the correct stale
  generation conflict after release. Metadata and both binding domains remain
  unchanged by the rejected overwrite, and the probe acquires exactly one
  public state lock.

### GREEN evidence

Post-CodeRabbit focused closure matrix:

```text
PYTHONPATH=src pytest -q \
  tests/test_host_probe.py::test_registry_get_unavailability_does_not_consume_probe_receipt \
  tests/test_host_probe.py::test_registry_get_definitive_missing_host_terminalizes_receipt \
  tests/test_host_probe.py::test_reconstructed_probe_owners_converge_after_each_persisted_boundary \
  tests/test_host_probe.py::test_remote_probe_separates_document_and_host_generation_without_wire_drift \
  tests/test_host_probe.py::test_generation_exhaustion_terminalizes_without_registry_mutation \
  tests/test_host_probe.py::test_remote_completion_stale_generation_terminalizes_without_registry_mutation \
  tests/test_host_probe.py::test_remote_completion_running_stale_generation_cannot_overwrite_new_probe \
  tests/test_host_probe.py::test_remote_completion_cross_host_rejection_cannot_terminalize_target_work \
  tests/test_host_probe.py::test_remote_completion_non_success_is_terminal_without_registry_mutation \
  tests/test_admin_operations.py::test_only_restart_reconciled_host_probe_can_be_resumed \
  tests/test_admin_operations.py::test_expired_restart_reconciled_host_probe_cannot_be_resumed \
  tests/test_admin_hosts.py::test_active_probe_owns_one_lock_and_rejects_contending_stale_cas \
  tests/test_control_center.py::test_host_probe_page_button_runs_production_flow_and_refreshes_only_terminal \
  tests/test_control_center.py::test_host_probe_submit_and_timer_scheduling_failures_are_visible \
  tests/test_control_center.py::ControlCenterViewModelTest::test_show_selects_ollama_page_before_refresh \
  tests/test_control_center.py::ControlCenterControllerTest::test_scheduler_registration_failure_reports_visible_unknown_result \
  tests/test_admin_cli_mcp_integration.py::test_real_host_probe_cli_uses_exact_parser_contract_and_internal_key \
  tests/test_admin_cli_mcp_integration.py::test_real_registered_host_probe_mcp_call_forwards_caller_key

36 passed in 13.67s
```

The matrix includes success/failed/unknown Registry-read retries, definitive
missing-host translation, all reconstructed completion boundaries, real
document/host generation divergence, maximum generation, stale/cross-host/
unknown byte preservation, narrow/expired reclaim, real lock contention, GTK
states/failures/refresh/index, and real CLI/MCP subprocess contracts.

Unfiltered directly changed test files:

```text
PYTHONPATH=src pytest -q tests/test_host_probe.py tests/test_admin_hosts.py \
  tests/test_admin_operations.py tests/test_control_center.py \
  tests/test_admin_cli_mcp_integration.py tests/test_control_catalog.py

281 passed, 36 subtests passed in 50.70s
```

Earlier Task-1..5 dependency regressions:

```text
PYTHONPATH=src pytest -q tests/test_agent_contracts.py \
  tests/test_agent_operations.py tests/test_agent_identity.py \
  tests/test_agent_http.py tests/test_agent_daemon.py \
  tests/test_host_agent_state.py tests/test_host_agent.py \
  tests/test_admin_daemon.py

218 passed in 170.03s
```

Preserved Host Admin route/scope/step-up selection:

```text
PYTHONPATH=src pytest -q tests/test_admin_contracts.py \
  tests/test_admin_http.py tests/test_admin_service.py \
  -k 'host and (probe or list or scope or step_up)'

6 passed, 243 deselected in 3.47s
```

Static verification:

```text
ruff check <all changed Python files>
All checks passed!

python -m compileall -q <all changed production Python files>
(clean)

git diff --check
(clean)
```

The exact-range and working-tree secret preflight reported zero matches before
editing. The complete uncommitted diff was scanned again before each external
review and reported zero matches without printing matched values.

### CodeRabbit and remaining concern

CodeRabbit CLI 0.7.5 was authenticated and run twice with
`coderabbit review --agent -t uncommitted`. The first pass returned one valid
minor expiry finding; it received a RED regression and minimal fix. The second
pass completed with zero findings.

No known Task-6 correctness concern remains. If GLib itself cannot register a
delivery, the controller now closes and directly invokes the bounded failure
callback so the Host-Probe state becomes UNKNOWN; a process whose GTK main
loop is already gone naturally cannot guarantee that the final pixels are
painted. The pre-existing unrelated `progress.md` modification was neither
edited nor staged.

## User-authorized exceptional production-graph closure round

This round is the one-time user-authorized exception after the 5/5 fix cap. It
closes only the six production-graph findings from `task-6-rereview-5.md` and
does not add a Task-7 public result wire or any Task-8 Ollama behavior. The
account hardgate passed before repository inspection: `CODEX_HOME` exactly
matched the authorized BW_Nufker profile. The governing plan/spec annotation
sidecars were checked and remain absent. The pre-existing `progress.md` change
was not edited.

### Canonical real production graph and RED evidence

The new `tests/test_host_probe_production_graph.py` crosses the actual Task-6
graph in process. `HostRegistry` provisions two real `AgentBindingV1` hosts,
leaving target host generation 1 and authoritative document generation 2. It
wires real `AdminOperationStore`, `AgentOperationStore`,
`RemoteHostProbeAdapter`, resolver-derived mTLS principal,
`AgentHttpApplication`, `RemoteHostProbeCompletionOwner`, `HostAgent`,
`HostAgentExecutor`, `HostAgentState`, and `HostAgentClient.poll()` /
`put_receipt()`. `InProcessAgentClient` overrides only `_request()` to exchange
JSON bytes with the application instead of TLS/socket bytes; the real client
DTO parsing, application parsing, principal conversion, stores, executor,
receipt construction, completion owner, and Registry remain in the path.

The test uses deterministic kernel fact providers, but neither evidence,
receipt, principal, Store, nor Registry state is fabricated. The target begins
as an Agent-only registration; no SSH probe is seeded. The completed receipt's
payload must equal the exact `HostProbeEvidenceV1.public()` projection. The
test also proves Admin is terminal when the real Agent Store completion is
invoked, host generation advances 1 -> 2, document generation advances 2 -> 3,
both private binding domains remain equal to their pre-probe documents, and
the same unchanged HostAgent polls successfully again.

Before production edits, the exact canonical command was:

```text
PYTHONPATH=src pytest -q \
  tests/test_host_probe_production_graph.py::test_real_production_graph_closes_remote_probe_and_repolls_after_generation_change
```

Progressive RED from that one graph exposed the production blockers in order:

```text
1 failed: AgentOperationError: host.operation_store_unavailable
  AgentOperationStore._now() rejected its default microsecond clock.

1 failed: TypeError: HostProbeExecutor() takes no arguments
  The real executor had no canonical collector/fact-provider contract.

1 failed: HostAgentError: resource.host_response_invalid
  Resolver AgentPrincipalV1 could not enter the exact-type operation Store.

1 failed: HostAgentError: host.arguments_invalid
  The real lease's immutable Mapping arguments exposed the old fake executor contract.

1 failed: expected Admin succeeded, got failed
  Agent-only record_active_probe() still required an SSH binding.

1 failed on the second poll: HostAgentError: resource.host_response_invalid
  Equal current lease_epoch and the incremented authoritative generation were incoherent.
```

After the minimal production fixes, the final real-graph set is:

```text
PYTHONPATH=src pytest -q tests/test_host_probe_production_graph.py
3 passed in 1.23s
```

The additional two tests are production-loop recovery graphs. One corrupts
the real Registry after resolver authentication but before receipt completion,
observes the sanitized rejected response, restores Registry bytes, reconstructs
all Master owners, advances only the deterministic retry clock, and drives the
ordinary HostAgent -> AgentHttpApplication -> Stores loop to convergence. The
other rejects Agent terminalization after Registry/Admin already completed,
then proves a later lease carries the new document generation and converges
without a second Registry write. Neither calls the completion owner directly.

### Six closure mappings

1. **Default clock.** `AgentOperationStore` now supplies canonical UTC seconds
   by default while the existing strict `_utc()` validator still rejects
   noncanonical external/request timestamps. A real Store/adapter regression
   uses no injected clock.

2. **Principal boundary and generation coherence.** `AgentHttpApplication`
   converts the exact resolver `admin_hosts.AgentPrincipalV1` to the distinct
   exact Store `agent_operations.AgentPrincipalV1` for poll and ordinary
   receipt paths. It verifies the resolver's current lease epoch exactly. A
   HostAgent may send an older configured document generation; the resolver's
   authenticated current generation becomes the Store poll fence and is
   returned in no-work/new-lease responses, so the running agent learns it.
   A future wire generation, lower/rotated epoch, stale response generation,
   or non-exact Store principal remains rejected.

3. **Real executor contract.** `HostProbeExecutor` accepts only exact private
   `{admin_operation_id, probe_schema}` arguments with a bounded operation
   token and exact integer schema 1. Validation does not collect twice.
   Dispatch uses `LocalHostProbeCollector` and returns the exact canonical
   `HostProbeEvidenceV1.public()` projection. Command, argv, shell, URL, path,
   and extra-key ingress remain impossible.

4. **Agent-only observation.** New agent registrations identify their distinct
   public transport as `outbound-pull-mtls`. `record_active_probe()` accepts a
   host with an SSH binding, an Agent binding, or both; it synthesizes neither.
   Under its existing one-lock transaction it keeps static registrations,
   SSH bindings, Agent bindings, and epoch history under their own owners and
   writes only the active observation plus document generation. Loading accepts
   Agent-only active observations while legacy SSH/Agent Store formats remain
   valid. The active digest intentionally covers only fresh observation fields;
   static registration and private binding state remain separate durable owners.

5. **Production reclamation and semantic receipt redelivery.** Polling invokes
   expired-lease reclamation. Equal current host-binding epoch is accepted;
   lower epoch is rejected. Each lease now durably records the resolver's
   authoritative document generation, with migration from legacy lease records.
   A saved terminal receipt can rebind only to a different later lease with a
   higher attempt, same operation/host/action/lease epoch/plan digest/arguments
   digest, nondecreasing document generation, and live deadline. The rebound
   receipt is persisted before return and preserves its terminal state, reason
   codes, result, and result digest. Counting fact providers prove one
   collection across rejection/reconstruction/redelivery. Ambiguous `unknown`
   receipts remain `unknown`; production polling terminalizes exhausted attempts
   as stable `host.attempts_exhausted` unknown.

6. **GTK delayed submit.** `_poll_host_probe()` catches delayed controller
   submission exceptions and false returns, renders `Host-Probe: UNKNOWN`,
   clears the active operation and poll count, returns from the callback, and
   never refreshes host data. The regression captures and invokes the actual
   delayed callback with `fleet_operation_status` submission raising.

### Final validation evidence

All commands below ran after the production behavior was finalized. Matrices
overlap intentionally; counts are invocation counts, not unique test IDs.

```text
# Six focused closures, including all three real production graphs
8 passed in 1.36s

# Unfiltered directly changed test files
270 passed, 5 subtests passed in 117.91s

# Existing Task-6 host-probe suite
52 passed in 1.96s

# Selected Task-1..5 contracts, identity and daemon dependencies
134 passed in 21.37s

# Preserved route/scope/HTTPS step-up/Unix selection
6 passed, 243 deselected in 2.76s

# Exact CLI --json / MCP caller-key / catalog contract
3 passed in 9.06s
```

The consolidated matrices in this subsection contain 473 passing pytest
invocations; the separately recorded standalone real-graph gate adds 3, for
476 passing invocations across the final recorded commands, plus 5 passing
subtests. Matrices overlap by design and include 243 explicit deselections.
Ruff passed on every changed Python file;
`compileall` passed on all six changed production modules; `git diff --check`
was clean. Corrected count-only secret scans reported zero suspected matches in
the committed Task-6 range, complete working diff (including the new untracked
E2E), and staged diff; no matched value was printed.

### CodeRabbit and remaining risk

CodeRabbit CLI 0.7.5 was authenticated and run with
`coderabbit review --agent -t uncommitted`. Its first pass suggested putting
static metadata into the active observation digest and relaxing exact terminal
generation fencing. Both were rejected as contrary to the preserved contracts:
static registration/binding owners are intentionally separate from fresh
observation digesting, and redelivery now receives a current-generation lease
rather than accepting a stale principal. Invariant comments were added. The
second uncommitted pass completed with **0 findings**.

The canonical E2E deliberately replaces TLS/socket bytes to remain deterministic
and in process. Separate real TLS, identity, HTTP, daemon, Store and restart
dependency suites remain green. Retry timing is deterministic only in the two
recovery tests; the canonical success graph uses the production Store clock
without injection. Production reclamation is poll-driven, so a host that never
polls cannot trigger immediate expiry maintenance; once polling resumes, the
durable queue converges. No known Task-6 correctness risk remains.

## Second exceptional lifecycle-fix round: orphan observations and attempt exhaustion

This user-authorized round is limited to the two Important lifecycle findings
in `task-6-rereview-exceptional.md`. It does not add a Task-7 result wire or
Task-8 Ollama behavior. The hard gate passed before edits: the worktree and
Git toplevel were the required SSD3 path, HEAD was exactly
`e5a3121808aafc4e3f9ed4ea8f02e50410e57bfc`, and `CODEX_HOME` selected the
canonical `RH_Privat` profile. The plan/spec annotation sidecars were checked
before the complete documents were read; neither sidecar exists. The
pre-existing `progress.md` modification was not edited.

### RED evidence

The regressions were added before production edits and run through the real
stores and polling path:

```text
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src pytest -q -p no:cacheprovider \
  tests/test_admin_hosts.py::test_agent_sync_last_removal_prunes_owned_active_observation_atomically \
  tests/test_admin_hosts.py::test_agent_sync_removal_preserves_observation_when_ssh_domain_remains \
  tests/test_host_probe_production_graph.py::test_attempt_exhaustion_reconciles_paired_admin_after_master_restart \
  tests/test_host_probe_production_graph.py::test_attempt_exhaustion_retries_one_shot_reconciliation_failure_on_poll \
  tests/test_host_probe_production_graph.py::test_attempt_exhaustion_reconciliation_is_scoped_to_polling_host

6 failed in 0.94s
```

The Agent-only removal returned successfully but immediate `HostRegistry.list()`
failed `control.host_store_unavailable`; the persisted observation no longer
had any registration/binding owner. Removing Agent state from a dual SSH+Agent
host instead failed the write because it also removed the registration still
required by the SSH binding. On exhaustion, reconstructed normal polling left
Admin `planned`; the Admin failure injection was never reached; a failed final
Agent write left Admin `planned`; and polling one host reclaimed another host
without involving either paired Admin owner.

### Closure architecture

`HostRegistry.synchronize_agent_bindings()` retains a static Agent
registration when the same ref still has a valid SSH binding. Inside its
existing single lock, it derives observation owners from the post-sync union
of SSH refs and Agent-binding refs, prunes only observations outside that
union, and performs the existing single document replacement. Agent-only
removal therefore writes empty registration/binding/observation collections at
document generation 3 and reopens cleanly. A dual host retains byte-equivalent
registration, SSH binding, and observation metadata while only its Agent
binding is removed. Epoch history remains a tombstone; existing CAS,
generation/epoch exhaustion, and no-write-on-error paths are unchanged.

The generic `AgentOperationStore` remains independent of
`AdminOperationStore`. It now exposes a private typed
`AgentAttemptExhaustionV1` callback boundary containing the exact Agent
operation, actual lease host, target host, kind/action, generations, attempt,
plan/argument digests, fixed arguments, lease ID/epoch, and deadline. An Agent
poll may process at most eight exhaustion callbacks and only for its own
authenticated host; other hosts retain their durable candidate for their own
poll. With no owner, the existing generic attempt-limit behavior remains
unchanged.

`AgentHttpApplication` supplies the existing
`RemoteHostProbeCompletionOwner` only on the production poll path. The owner
accepts exactly `host.probe/collect`, requires lease host equal to target,
requires exactly `admin_operation_id` plus `probe_schema=1`, and verifies the
paired Admin kind and plan digest. It then reuses the existing restart-safe
Admin failure transition to finish the Admin operation as
`failed/host.probe_unknown`. Only after that returns does the Agent Store
durably write `unknown/host.attempts_exhausted`.

No external receipt or evidence is fabricated. The Registry is not read or
mutated during exhaustion. A failed Admin boundary leaves the Agent lease
durably retryable. A failed final Agent write leaves the Admin terminal and the
Agent lease retryable; the next ordinary poll recognizes the terminal Admin
state and completes the Agent transition. Reconstructing Registry, Admin Store,
Agent Store, application, and owner before the final poll converges through
the same path. Agent operation schema version 1 and HostRegistry schema version
3 are unchanged, and the eight-attempt limit retains its original meaning.

### GREEN and preservation evidence

```text
# Exact lifecycle regressions
6 passed in 1.99s

# Complete directly affected HostRegistry file
131 passed in 2.28s

# Complete host-probe and real production-graph files
59 passed in 3.18s

# Complete Agent operation and Agent HTTP files
39 passed in 69.88s

# Existing Admin transaction/restart owner file
38 passed in 50.59s

# Selected Task-1--5 contracts, identity, daemon, HostAgent state/client,
# executor, and Admin daemon dependencies
185 passed in 69.63s

# Route/scope/HTTPS step-up, exact CLI/MCP/catalog, and GTK terminal rendering
10 passed, 244 deselected in 18.83s
```

These recorded post-fix commands contain 468 passing pytest invocations, with
the six focused invocations intentionally repeated in their complete affected
files, plus 244 deselections. The production-graph tests cross real
`HostRegistry`, `AdminOperationStore`, `AgentOperationStore`,
`RemoteHostProbeAdapter`, `AgentHttpApplication`, and
`RemoteHostProbeCompletionOwner` through serialized ordinary polls. They prove
restart reconstruction, Admin and final-Agent one-shot failure retry, exact
terminal reasons, no Registry mutation, and no cross-host reconciliation.

Ruff passed all six changed Python code/test files. `compileall` passed the four
changed production modules with its cache in tmpfs. `git diff --check` passed.
The count-only suspected-secret scan over the authorized source/test diff
reported 0 matches and printed no matched values.

### CodeRabbit and residual risk

CodeRabbit CLI 0.7.5 was authenticated and run uncommitted with separate
`src/codex_master` and `tests` directory scopes. This excluded the protected
pre-existing `progress.md` diff, whose count-only preflight contains one
permissive substring match; every authorized file reported zero suspected
matches. The tests review completed with 0 findings. The first source review
suggested reconciling other hosts during the current host's poll. That finding
was rejected as contrary to the explicit no-cross-host-reconciliation contract
and the authenticated host boundary. After an invariant comment, the source
rerun completed with 0 findings.

Reclamation remains deliberately poll-driven and host-scoped: a host that
never polls cannot ask another authenticated host to reconcile its lifecycle.
The Admin-then-Agent transition spans two durable stores rather than one atomic
write, so availability failures can expose the documented intermediate state;
ordinary later polls are the tested recovery mechanism. The production graph
still replaces only TLS/socket I/O in process; the separate identity, HTTP,
daemon, client, and restart suites passed. Independent review, not this report,
decides Task-6 closure.

## Lifecycle deadline follow-up: I2-L1 and I2-L2

This continuation took over the intact TDD worktree after the original
implementer reached an explicit account usage limit. The user-authorized
fallback profile marker was confirmed before repository work. The worktree and
Git toplevel were the required SSD3 path and HEAD was exactly
`54fcc5e4087d0db58e311eba0ea3335c6834f681`. The starting SHA-256 of the
pre-existing `progress.md` modification was
`1e17c131349fadfb937f52806c2c74ac4c47442c88f474d8c8b46df9363021bc`;
it remained byte-identical and was never staged.

### RED and takeover evidence

Before production edits, the original session ran the exact seven selected
test nodes added for this follow-up. The three-case parametrized Admin node
made nine invocations, all of which failed as expected: migrated terminal
Agent operations were undiscoverable, stored operation deadlines did not stop
new leases, the Admin Store lacked an expired-plan transition, and both real
production graphs failed to converge.

At takeover, the inherited partial GREEN passed eight of those nine
invocations. The slow eighth-lease graph still left Admin `planned`, proving
that detection existed but the production HTTP/owner path was not wired.
Caller self-review added and observed further focused REDs before their fixes:

- a real adapter's five-minute Agent deadline returned a retryable poll error
  while its Admin plan was still live;
- a migrated terminal split was offered to the owner again on every poll,
  consuming the same bounded reconciliation slot repeatedly;
- the migrated split still looped on `control.plan_expired` when reconstruction
  and first polling happened after the Admin lifetime;
- a dead-owner failure transition reconstructed after expiry could not be
  terminalized from its exact `partial/control.restart_reconciled` state.

### Closure design

`AgentOperationStore` now treats the persisted operation deadline separately
from eight-attempt exhaustion. It never leases a queued record at or after that
deadline. Ownerless polling retains generic Store behavior and terminalizes the
record as `unknown/host.lease_expired`. Production polling instead builds a
frozen, fully fenced deadline context, releases the Agent state lock, invokes
the exact host-probe owner, and only then commits the same Agent terminal state.
Queued and leased deadline candidates share the existing maximum of eight
owner callbacks per authenticated same-host poll.

For I2-L1, same-host polling also discovers the valid base-compatible
`unknown/host.attempts_exhausted` record while preserving its persisted view.
Successful migrated reconciliations are remembered only within the current
Store instance so later polls can advance beyond the first bounded batch.
Reconstruction deliberately forgets that optimization and safely revalidates
the idempotent Admin terminal state; no durable schema change or Registry
mutation is introduced.

`AgentHttpApplication` supplies both typed lifecycle callbacks from the one
production `RemoteHostProbeCompletionOwner`. That owner validates exact
`host.probe/collect`, lease host equals target, fixed arguments, paired Admin
kind, generation owner and plan digest. A live Admin plan uses the existing
restart-safe failure transition. If normal `begin()` correctly reports
`control.plan_expired`, the new narrow `AdminOperationStore.expire_host_probe()`
transition accepts only the exact expired pair: `hosts.probe`, the expected
generation and plan digest, the one fixed step, no owner or resulting
generation, and either the original `planned/control.plan_ready` shape or the
two safe failure-reconstruction shapes (`not_attempted`, or already failed as
`host.probe_unknown`). It is terminal-idempotent and does not weaken `begin()`
or `resume_host_probe()` expiry rules.

The observable terminal reasons remain distinct: Admin becomes
`failed/host.probe_unknown`; operation-deadline expiry becomes Agent
`unknown/host.lease_expired`; ordinary eight-attempt exhaustion remains Agent
`unknown/host.attempts_exhausted`. No receipt or evidence is fabricated. Every
production graph asserts Registry bytes are unchanged, and the slow graph
observes Admin `failed` at the first Agent terminal write.

### Final validation

Every pytest command used
`PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src pytest -q -p no:cacheprovider`.

```text
# Complete changed and directly adjacent files
tests/test_agent_operations.py tests/test_agent_http.py
tests/test_admin_operations.py tests/test_host_probe.py
tests/test_host_probe_production_graph.py
147 passed in 51.77s

# Task-1--5 contract, identity, daemon, HostAgent state/client/executor deps
185 passed in 33.75s

# Host route/scope/HTTPS step-up/Unix selection
6 passed, 243 deselected in 1.79s

# Exact CLI --json, MCP caller key, catalog, six GTK/Ollama preservation nodes
9 passed in 3.53s
```

These non-overlapping final matrices contain 347 passing invocations plus 243
explicit deselections. The focused lifecycle matrix also passed all inherited
nodes and the additional live-plan branch; its invocations overlap the complete
affected files and are not added to that total.

Ruff passed all seven changed Python files. `compileall` passed the four changed
production modules with its bytecode cache isolated in tmpfs and removed.
`git diff --check` was clean. The count-only suspected-secret scan over all
owned production/test/report changes reported zero matches and printed no
matched values. No external reviewer or subagent was invoked; manual
self-review traced every `poll()` caller, both lifecycle callbacks, all Admin
transition callers, terminal ordering, lock boundaries, exact-host selection,
and reconstruction paths.

### Residual risks

- Reconciliation remains authenticated-poll driven. A host that never polls
  cannot reconcile its work, and another host is intentionally forbidden from
  doing so.
- The in-process production graphs replace TLS/socket byte transport. Separate
  identity, HTTP, client and daemon suites passed, but this is not a live
  two-daemon mTLS E2E.
- Admin-before-Agent terminalization spans two durable stores. A crash can
  expose the intended intermediate state; exact planned, running,
  restart-reconciled and already-terminal retry shapes now converge on a later
  ordinary poll.
- The per-Store migrated-reconciliation memory is intentionally not durable.
  The first poll after each reconstruction may revalidate up to eight already
  reconciled pairs, while subsequent polls in that process advance to later
  candidates without changing schema-v1 Agent bytes.
