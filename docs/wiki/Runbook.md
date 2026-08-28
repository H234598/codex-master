# Runbook

> Canonical repository source: `docs/wiki/Runbook.md`  
> Last verified: 2026-08-14 against the local source tree  
> Publication status: local source; not yet published to GitHub Wiki

Use structured Masterjet commands and preserve their redacted output as the
operational record. Do not inspect private state or raw tmux logs as a shortcut.

## Read-only diagnosis

From the repository root:

```sh
./bin/codex-master-mcp doctor
./bin/codex-master-mcp status
./bin/codex-master-mcp integration-status
./bin/codex-master-mcp plugin-status
./bin/codex-master-mcp namespace-status
./bin/codex-master-mcp timeout-policy
```

These commands diagnose different boundaries. A healthy server process does
not by itself prove fresh plugin state, active-client visibility, provider
availability, or an enabled Hive.

## Safe assignment flow

1. Inspect current status, capabilities, selection options, and resource-admission evidence.
2. Define the smallest read scope and exact persistent write paths.
3. Run `scope-check` before a write assignment.
4. Prefer `assign-readonly`, `assign-live-data`, or `assign-write` over raw send.
5. Wait on the returned assignment ID, then request the explicit redacted
   assignment report.
6. Verify the actual diff and tests independently; an Agentin success message
   is not completion evidence.

The complete command and error reference is the
[`codex-master-mcp(1)` source](../../man/man1/codex-master-mcp.1). Resolver
operations are documented in [Selection operations](../operations/selection-operations.md).

## Mutation boundary

- Lease-protected Agentin assignments are permitted only within delegated
  authority, scope, write paths, admission, and capability rules.
- Destructive pool or home operations require explicit target verification and
  separate authorization.
- Only the authorized Queen may restart or reload Masterjet, install it, or
  synchronize the plugin cache. Other roles may gather evidence and recommend
  that action, but must not execute it.

## Publication boundary

These files are local sources. Publishing them requires an initialized GitHub
Wiki remote, an authorized publisher, a reviewed source-to-page mapping, and a
post-publication link check. No command in this runbook publishes documentation.
