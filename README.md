# The Hive

The Hive is a local, data-sparse MCP control plane for a sleeping Codex-agent
fleet. Its source defines typed coordination, admission, selection, and
bounded-reporting surfaces; raw terminal output is outside the normal public
response boundary.

This repository documents source-controlled contracts and operational
boundaries. It does not by itself demonstrate a connected provider, activated
service, installation, or running runtime.

## Start here

- [Documentation index](docs/README.md) — normal repository navigation for
  architecture, configuration, operations, security, and development.
- [Installation boundary](docs/installation.md) — the reviewed, attested
  runtime-image boundary.
- [Operations runbook](docs/operations/runbook.md) — evidence-first operating
  and recovery procedures.
- [Security and trust boundaries](docs/security/hive-security.md) — authority,
  state, and data-exposure constraints.

## Repository entry points

The Python package is named `the-hive` and exposes `the-hive-mcp`,
`the-hive-admin`, `the-hive-agent-api`, and `the-hive-host-agent`. The
checked-in [`.mcp.json`](.mcp.json) selects the deployment-configured stable
local launcher; [`bin/the-hive-mcp`](bin/the-hive-mcp) is an attested runtime
wrapper, not a general checkout entry point.

Versioned configuration includes [codex-hive.json](codex-hive.json),
[codex-agent-classes.json](codex-agent-classes.json),
[codex-agent-pool.json](codex-agent-pool.json), and
[codex-model-policy.json](codex-model-policy.json). Their change boundary is
documented in [configuration](docs/configuration.md).

## Roadmap

The compact end-to-end project timeline, including the single marked project
position and all planned principal stages, is [ROADMAP.md](ROADMAP.md).
