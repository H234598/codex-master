# The Hive configuration

The checked-in configuration is source-controlled input, not a credential
store and not proof that a fleet, provider, or control plane is active. The
current files are:

- [`codex-hive.json`](../codex-hive.json): Hive repositories, principals, mode,
  and feature flags.
- [`codex-agent-classes.json`](../codex-agent-classes.json): the agent-class
  catalog.
- [`codex-model-policy.json`](../codex-model-policy.json): model policy.
- [`codex-agent-pool.json`](../codex-agent-pool.json): pool specification.

The Hive configuration and class-catalog loaders require absolute,
non-symlink paths and reject malformed or unexpected data. Treat a loader or
runtime rejection as a blocked configuration state; do not work around it by
copying files into private runtime state or weakening a path check.

## Current checked-in state

`codex-hive.json` declares `mode: "enforced"`, while the checked-in selection
flags `sp0_passive`, `sp1_deadline`, `sp2_secondary_model`, and `sp3_fairness`
are all `false`. This establishes neither a live reservation nor a right to
start, stop, interrupt, or preempt work. Selection and pilot decisions use
current authority and runtime evidence and fail closed when that evidence is
missing, stale, malformed, or insufficient.

The model policy and pool specification describe eligible product inputs. They
do not provision credentials, accounts, or managed homes. Follow trusted owner
instructions for every secret or account-provisioning step; no such procedure
is verified by this documentation.

## Change boundary

Review a configuration change together with its schema, referenced catalog or
policy, and focused tests. A checked-in edit does not apply itself to an
installed runtime. Do not directly edit private state, release generations,
leases, or generated user-unit files to force a change.

The runtime source still recognizes `CODEX_MASTER_MCP_STATE`, then
`CODEX_AGENT_MCP_STATE`, and otherwise uses the legacy default state-root name
`~/.local/state/codex-master-mcp`. These are technical compatibility contracts,
not The-Hive product names or portable configuration instructions.

For the installation boundary, see [installation](installation.md). For
focused local contract checks, see [development](development.md); for blocked
runtime evidence, see [troubleshooting](operations/troubleshooting.md).
