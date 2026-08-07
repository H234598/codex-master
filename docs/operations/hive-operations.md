# Hive Operations

The Hive is a bounded control plane for typed principals, repository bindings,
grants, workpackages, queue state, admissions, and reports. The default MCP
surface is read-only and returns `raw_output: not_returned`.

Useful local checks:

```sh
./bin/codex-master-mcp tools
./bin/codex-master-mcp hive status
./bin/codex-master-mcp hive doctor
./bin/codex-master-mcp hive migration-status
./bin/codex-master-mcp hive rollback --dry-run
./bin/codex-master-mcp selection-status
./bin/codex-master-mcp selection-policy-status
./bin/codex-master-mcp reset-anchor-run --dry-run --anchor-key sha256:<64-hex>
```

Global requests are planned as independent repository dispatches. Unknown
repositories and breaking/destructive constraints remain blocked. A productive
multi-repository saga needs an explicit registry, pilot allowlist, user gates,
and injected create/execute/compensation callbacks; there is no global commit
or hidden atomicity.

Cooperative pause is checkpointed. A work-orchestration request must be
followed by a typed safe progress report before a workpackage can enter
`paused`. Selection fairness and SP0–SP3 never stop, interrupt, restart, or
take over a lease. Resuming requires fresh admission and scope revalidation.

Private state is bounded, lock-protected, no-follow, and redacted at public
boundaries. Real provider credentials and external pilot approval remain
operational gates.

## Runtime assembly and recovery

The server-side admission adapter must be built from one explicit
`HiveRuntime` bundle containing the validated Hive config, principal registry,
repository registry, and authority engine. `build_current_hive_runtime` keeps
local repository roots caller-supplied because paths are not part of the
public configuration; principal materialization is opt-in and exact config
parity is required.

When an executor is attached, pass a private `FileCompletionJournal` to the
runtime adapter. It durably records only a bounded admission revision and
opaque operation/result digests. A started record without a completed record
is unresolved after a crash and is never guessed as successful. A completed
record can be consumed by `SelectionService.reconcile_incomplete()` from a
fresh process. Provider responses, prompts, credentials, paths, and result
values are not written to the journal.

`create_assignment_admission()` is the explicit bridge from a verified
`QueenAssignmentPlan`, `WorkPackage`, `AssignmentIntent`, `DelegationGrant`,
and repository registry to one immutable `PLANNED` admission. It checks the
cross-object identities and the live grant without consuming it, binds the
concrete write paths to the scope digest, and carries the workpackage version
and grant binding digest forward. It does not reserve capacity, claim a lease,
start a provider, or mutate a repository. The server authority gate rejects a
record whose grant digest has changed since materialization.

Every `FileAdmissionStore` lifecycle transition goes through the same
cross-process lock and atomic state replacement as the initial reservation.
That includes revalidation, admission, execution, finalization, denial and
compensation; a fresh process therefore cannot observe a stale in-memory
state after a transition.

`build_server_selection_service()` is the explicit server factory for this
durable path. It couples `FileAdmissionStore` to the fixed
`ServerAdmissionRuntime` gate order, but it is not called by an MCP tool and
does not enable execution by itself. Missing Hive bindings therefore remain a
normal fail-closed result.

Completion records additionally carry one digest over the assignment,
workpackage, grant, scope, resource and lease bindings. The digest is checked
before idempotent completion and during fresh-process recovery; the journal
stores none of those private values themselves.

For a productive callback, use `build_server_lease_executor()` explicitly with
an allowlisted operation map. Immediately before the named callback runs, it
reads the agent lease again and compares the state and, when present, the
immutable lease id from the admission record. The adapter passes that private
snapshot to the callback but never claims, releases, starts, sends, or invokes
a provider on its own. The callback must route to an existing low-level
operation and own its completion/release behavior; direct calls still require
an `EXECUTING` admission record.

`execute_server_hive_assignment()` is the explicit bridge for this full local
flow. It creates a fresh planned admission from the authoritative Hive
objects, builds the persistent SelectionService, and supplies the allowlisted
lease executor. Retry attempts receive distinct admission IDs; no MCP tool
calls the bridge implicitly, and no provider operation exists unless the
caller supplies the operation callback.
