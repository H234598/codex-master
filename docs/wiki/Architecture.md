# Architecture

> Canonical repository source: `docs/wiki/Architecture.md`  
> Last verified: 2026-08-14 against the local source tree  
> Publication status: local source; not yet published to GitHub Wiki

Codex Master, also called Masterjet or The Hive in compatibility surfaces, is a
local MCP control plane for a sleeping, scalable Agentinnen fleet.

## Components

- **Fleet Registry:** authoritative checked-in shape for configured accounts,
  providers, series, and policy bindings. Runtime secrets remain outside it.
- **Central resolver:** turns class, lifecycle, task complexity, model, effort,
  account availability, and authority into one effective offered tuple.
- **Masterjet MCP:** exposes bounded diagnostics and lease-protected mutations.
- **Hive control plane:** defines principals, authority, admission, selection,
  assignments, queueing, decisions, and recovery contracts.
- **Agentinnen backends:** managed Codex sessions and bounded headless jobs.
  Assignment scope and explicit write paths are their mutation boundary.

## Request flow

1. Read current selection options instead of reconstructing a model matrix.
2. Resolve the requested or default class/lifecycle/model/effort tuple once.
3. Apply authority, capability, account, and admission checks.
4. Acquire the Agentin lease and bind the assignment to its approved scope.
5. Execute through the selected backend and expose only bounded metadata.
6. Retrieve explicit reports through the redacted assignment-report boundary.

Recovery and reconciliation handle interrupted local transitions; they do not
turn missing external provider evidence into success.

## State and trust boundaries

- Secrets, leases, raw logs, usage snapshots, and assignment metadata use
  private local state and are not documentation inputs.
- Public MCP responses are data-sparse and redact local paths and raw output.
- Read-only status is not a reservation. Mutations must recheck live state.
- A green local suite does not prove an enabled Hive, provider credentials, or
  an end-to-end external recovery path.

## Canonical detail

- [Project overview and CLI](../../README.md)
- [Agentinnen pool and auth boundaries](../agent-pool.md)
- [Selection operations](../operations/selection-operations.md)
- [Hive operations](../operations/hive-operations.md)
- [Hive security](../security/hive-security.md)
- [Selection privacy](../security/selection-privacy.md)
