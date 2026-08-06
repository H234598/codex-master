# Account-aware Selection

Selection treats an account as an opaque, locally derived identity. Public
responses expose agent/model/band and reason codes, never account keys,
provider credentials, prompts, or terminal output.

The pipeline is deliberately two-dimensional:

- DP is work priority: DP0–DP3, deadline, dependencies, and queue fairness.
- SP is resource preference: passive reset evidence, verified short windows,
  secondary-model eligibility, and account fairness.

`preview_selection` is deterministic and read-only. `AdmissionMode.OFF` and
`SHADOW` do not reserve resources. `ENFORCED` still requires every explicit
authority, repository, scope, account, model, usage, lease, process, auth, and
config gate through `ServerAdmissionRuntime`.

Usage-v2 payloads must be typed and fresh. Unknown or stale semantics are
excluded from SP0/SP1 rather than guessed. SP2 permits a secondary-simple model
only for positively simple work and an enabled policy flag; complex or unknown
work remains primary-only.

The passive reset anchor can be previewed with `reset-anchor-run --dry-run`.
Its execution path remains blocked by `selection_proactive_anchor_safety_gate`
until a separately verified sandbox, token budget, runtime limit, and kill
switch contract exists.

The private policy example is loaded through
`codex_master.selection.config.load_selection_policy`. The loader rejects
unknown fields, duplicate allowlist entries, symlink/hardlink files, stale
types, and out-of-range reservation/freshness values. It maps only passive
feature flags into the deterministic core; `allows_pilot()` is an allowlist
check, not authority, credential, reservation, or provider evidence. Shadow,
kill-switch, and missing gates therefore remain closed for execution.

When the private policy file is present, the server preview applies it as an
upper bound: requested SP flags cannot exceed configured featureflags and an
`enforced` request is capped by the configured mode. An active kill-switch
clears every SP flag and forces `off`. The wrapper exposes this decision via
`selection-policy-status` and includes only a redacted policy digest in the
selection preview.

The current private-policy schema uses `disabled`, `shadow`, and `enforced` as
the execution-boundary modes (`off`, `shadow`, and `enforced` internally).
The broader Hive design terms `observe` and `auto` are not accepted aliases:
their runtime semantics are not defined by this contract, so they remain
fail-closed until a separate policy decision specifies their gates.
