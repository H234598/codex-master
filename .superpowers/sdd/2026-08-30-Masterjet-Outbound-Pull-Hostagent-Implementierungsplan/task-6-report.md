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
