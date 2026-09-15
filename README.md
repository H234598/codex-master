# The Hive

The Hive is a local, data-sparse MCP control plane for a sleeping Codex
Agentinnen fleet. It combines typed Hive coordination with lifecycle and
selection surfaces for locally managed agents; raw terminal output is not part
of the normal public response boundary.

This document describes the repository snapshot, not a claim that a runtime,
provider, service unit, pilot, or CI run is live on any machine.

## What is in this repository

- The Python package is named `the-hive` and exposes the `the-hive-mcp`,
  `the-hive-admin`, `the-hive-agent-api`, and `the-hive-host-agent` entry
  points.
- The repository ships the The Hive MCP configuration in
  [`.mcp.json`](.mcp.json). Its `the-hive-mcp` entry uses the
  deployment-configured stable local launcher with no arguments.
- The source includes a typed Hive control plane for principals, repository
  bindings, grants, work packages, admission, queues, and bounded reports.
- The source also contains a versioned runtime-image and launcher contract,
  agent-pool support, selection policy inputs, and systemd unit artifacts.

The authoritative overview of integrated, prepared, blocked, and later work
is [ROADMAP.md](ROADMAP.md). The documentation index is
[docs/README.md](docs/README.md).

## Quick start

1. Read the [installation](#installation) and
   [security and trust boundaries](#security-and-trust-boundaries) sections.
2. Have the intended local user materialize the private Runtime Image with the
   reviewed installer below; it does not activate a unit.
3. Configure the MCP client from the checked-in [`.mcp.json`](.mcp.json),
   which points at the attested stable launcher rather than a checkout.
4. Use the [operations runbook](docs/operations/runbook.md),
   [recovery boundary](docs/operations/recovery.md), and
   [troubleshooting guide](docs/operations/troubleshooting.md) for their
   evidence-first operational boundaries.

## Installation

The project requires Python 3.11 or later according to
[pyproject.toml](pyproject.toml). The checked-in runtime-image installer is:

```sh
./scripts/the-hive-hive-hourly-probe-install --home /absolute/path/to/home
```

This is a state-changing installation command: it must be reviewed and run
only by the operator of the target home. The repository snapshot alone cannot
show whether an installation completed or whether its resulting runtime is
safe for a particular host.

The fuller source-backed installation boundary is in
[docs/installation.md](docs/installation.md). It does not add a generic live
installation recipe.

The productive MCP entry is the stable launcher selected by [`.mcp.json`](.mcp.json).
Do not use a source checkout as an MCP entrypoint. In particular,
[`bin/the-hive-mcp`](bin/the-hive-mcp) is an internal attested runtime wrapper:
it requires a release root, generation, and manifest digest before any further
arguments. It is not the normal operator command.

## Basic configuration

The versioned configuration inputs are:

- [codex-hive.json](codex-hive.json) for Hive configuration;
- [codex-agent-classes.json](codex-agent-classes.json) for the class catalog;
- [codex-agent-pool.json](codex-agent-pool.json) for the pool specification;
- [codex-model-policy.json](codex-model-policy.json) for model selection; and
- [schemas/](schemas/) and [examples/](examples/) for their checked-in
  contracts and examples.

The Hive state root resolves `CODEX_MASTER_MCP_STATE` first, then
`CODEX_AGENT_MCP_STATE`, and otherwise
`~/.local/state/codex-master-mcp`; the historical directory and environment
names are technical compatibility paths, not the active product name. Do not
rename or relocate them without a separately verified runtime migration.

Configuration changes are security-sensitive. Validate the applicable schema,
repository binding, principal and grant relationships, and current runtime
evidence before allowing a mutation. The source has no basis for treating a
checked-in example or a committed configuration file as an approved live
deployment.

See [docs/configuration.md](docs/configuration.md) for the complete
source-controlled configuration boundary and its related schema links.

## Operation

Normal operation starts the MCP server through the stable launcher declared in
[`.mcp.json`](.mcp.json). Begin with read-only status and diagnosis, then use
the scoped procedure that applies to the affected component:

- [Hive operations](docs/operations/hive-operations.md) for the Hive control
  plane and its admission boundary;
- [agent-pool operations](docs/agent-pool.md) for local sleeping agents;
- [selection operations](docs/operations/selection-operations.md) for
  account-aware selection; and
- [home-broker runbook](docs/operations/the-hive-home-broker.md) for the
  offline broker package boundary.

For the complete operating, recovery, and failure-evidence boundaries, use
[the operations runbook](docs/operations/runbook.md),
[recovery](docs/operations/recovery.md), and
[troubleshooting](docs/operations/troubleshooting.md). They are not permission
to substitute an old command, activate a unit, or alter private state.

## Security and trust boundaries

- The stable launcher checks the current release pointer, manifest digest, and
  release entrypoint before it delegates to the attested runtime wrapper.
- The Hive model validates typed principals, parent and repository bindings,
  scopes, capabilities, grants, revisions, and bounded private state. Missing,
  stale, malformed, or unavailable evidence fails closed.
- Public responses are intentionally data-sparse: credentials, prompts,
  terminal output, local absolute roots, and secret material are outside the
  normal public boundary.
- The Agent API source requires mutual TLS 1.3. The Host Agent source initiates
  outbound TLS 1.3 with hostname and certificate verification, disables proxy
  use, and rejects redirects; these are source contracts, not evidence of a
  connected host or live service.
- Productive admission is not implicit. The server-side runtime requires all
  configured gates and an explicitly injected low-level operation; it does not
  start a provider, claim a lease, or execute a callback on its own.

See [Hive security](docs/security/hive-security.md),
[selection privacy](docs/security/selection-privacy.md), and
[Hive operations](docs/operations/hive-operations.md) for the source-backed
details and operational constraints.

## Resource-monitor delivery boundary

The checked-in source states: the-hive-resource-monitor.service is delivered but not installed or active.
No installer, MCP tool, or standard test enables or starts this unit implicitly;
an explicit, authorized resource-monitor installation path is a separate
state-changing operation.

The tracked unit hardening declares ProtectHome=tmpfs and PrivatePIDs=yes hide unrelated Home and process data.
Its BindReadOnlyPaths exposes only the installed monitor layout, fixed catalogs,
and central Hive state. Those source directives are neither evidence of an
installed unit nor permission to activate, reload, or inspect a local service.

## Status and limitations

The current product-source snapshot includes a canonical, redacted
`DiagnosticV2` contract, a bounded BUS-S0 event-type contract, and the local,
fail-closed BUS-S1 Slice-A Store-Foundation (`HiveBusStore`) with its focused
test. Current-Main snapshot `e7b3286ab0752b3f110f1fa02d0f366aa6f710cb` (tree
`184da8c6e517b6021079a6d2a9d8c55338c125e3`) carries the following bounded
source/test evidence: `a65fe3972f7859e808ec6f09a39808fa240d4f49`
source-integrates that Store-Foundation; the preceding
`4eef3d90db78f72efb96d1888d15af8c024cd5a0` registers only
`BUS_E_CURSOR_CONFLICT`, `BUS_E_DELIVERY_STALE`, and `BUS_E_POISON` in
`DiagnosticV2`; `9e0ce708a803ce6f6b961ea678e367cc31e2888c` source-integrates
Delivery-/Effectsicherheitslogik; and current Main adds four additive
Testmatrixnachweise in `tests/test_hive_bus_store.py`. This establishes only
source/test artifacts, code registrations, and test evidence; it does not
establish a deployed diagnostics or bus service.

Several operational conditions remain external or explicitly unavailable:

- A logical Queen runtime adapter is not materialized; the controller reports
  a blocker instead of simulating a spawn.
- Provider availability, credentials, pilot approval, current gates, and
  operator acceptance are runtime facts that this repository cannot attest.
- Multi-repository side effects require confirmed gates, pilot allowlists, and
  explicitly injected callbacks. No hidden global commit is provided.
- CI must not be reported green from this snapshot. The current workflow still
  asserts the historical `codex-master` plugin and app keys while the
  checked-in manifests use The Hive identity; that conflict requires a
  separate CI correction and verification.

Historical identifiers occur only where they are required to describe current
compatibility or the CI blocker above; they are not active The Hive operator
instructions.

## Documentation

Start at [docs/README.md](docs/README.md) for the normal repository
documentation navigation. It separates product and operator material from
historical plans, templates, and handoffs.

## Evidence scope

The historical documentation parity and consolidation basis is
`b5def7d6156d7862606a0edcbd7226652cf4833f`. Current product-source status is
verified against Current-Main snapshot
`e7b3286ab0752b3f110f1fa02d0f366aa6f710cb` (tree
`184da8c6e517b6021079a6d2a9d8c55338c125e3`): [pyproject.toml](pyproject.toml),
[`.mcp.json`](.mcp.json), [`bin/the-hive-mcp`](bin/the-hive-mcp),
[`bin/the-hive-mcp-stable`](bin/the-hive-mcp-stable),
[src/the_hive/admission_runtime.py](src/the_hive/admission_runtime.py),
[src/the_hive/agent_daemon.py](src/the_hive/agent_daemon.py),
[src/the_hive/host_agent.py](src/the_hive/host_agent.py),
[src/the_hive/diagnostics.py](src/the_hive/diagnostics.py),
[src/the_hive/hive/bus_types.py](src/the_hive/hive/bus_types.py),
`src/the_hive/hive/bus_store.py`, and `tests/test_hive_bus_store.py`.

In that product-source comparison,
`a65fe3972f7859e808ec6f09a39808fa240d4f49` adds the local, fail-closed BUS-S1
Slice-A Store-Foundation (`HiveBusStore`) and its focused test. The preceding
`4eef3d90db78f72efb96d1888d15af8c024cd5a0` adds only the three additional
`DiagnosticV2` code registrations `BUS_E_CURSOR_CONFLICT`,
`BUS_E_DELIVERY_STALE`, and `BUS_E_POISON`; then
`9e0ce708a803ce6f6b961ea678e367cc31e2888c` source-integrates
Delivery-/Effectsicherheitslogik. Current-Main
`e7b3286ab0752b3f110f1fa02d0f366aa6f710cb` (tree
`184da8c6e517b6021079a6d2a9d8c55338c125e3`) adds four additive
Testmatrixnachweise in `tests/test_hive_bus_store.py`. This is source/test
evidence only, not evidence of a running bus, broker, service, or deployment.
