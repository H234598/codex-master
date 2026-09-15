# The Hive Architecture

This page describes checked-in architecture contracts for **The Hive**. It is
not evidence that a local or external runtime is installed, enabled, connected,
or healthy.

## Orientation

The distributable package is [`the-hive`](../pyproject.toml), with source in
[`src/the_hive/`](../src/the_hive/). The package declares `the-hive-mcp` as a
console entry point. The repository's [`bin/the-hive-mcp`](../bin/the-hive-mcp)
is an attested release wrapper: it requires a release root, generation, and
manifest digest before any remaining arguments. It is therefore not a
copy-and-paste direct invocation for a checkout.

The checked-in configuration surface consists of:

- [`codex-hive.json`](../codex-hive.json) for Hive configuration;
- [`codex-agent-classes.json`](../codex-agent-classes.json) for the class
  catalog;
- [`codex-model-policy.json`](../codex-model-policy.json) for model policy;
  and
- [`codex-agent-pool.json`](../codex-agent-pool.json) for the pool
  specification.

These files describe source-controlled inputs. They do not establish provider
credentials, account availability, an active pool, or an enabled control
plane. The server source retains the technical legacy state-root default
`~/.local/state/codex-master-mcp`; this path is an implementation compatibility
detail, not a new The-Hive identity or an operator instruction.

## Components and boundaries

- The fleet-related source and its local recovery implementation live in
  [`src/the_hive/fleet_service.py`](../src/the_hive/fleet_service.py) and
  [`src/the_hive/fleet_recovery.py`](../src/the_hive/fleet_recovery.py).
- Resolver and selection code lives under
  [`src/the_hive/selection/`](../src/the_hive/selection/) and in the server
  entry point. It derives an offered or effective selection from the
  checked-in policy plus current admissibility evidence.
- The Hive layer has distinct configuration, runtime, admission, dispatch, and
  event-store source modules under [`src/the_hive/hive/`](../src/the_hive/hive/)
  and [`src/the_hive/admission_runtime.py`](../src/the_hive/admission_runtime.py).
- The home-broker artifacts are a separate static release boundary. Their
  offline-review constraints are documented in the
  [home-broker runbook](operations/the-hive-home-broker.md).

Private state, credentials, leases, raw logs, prompts, and exact local roots
are not documentation inputs. Public-boundary expectations are described in
[Hive security](security/hive-security.md) and
[selection privacy](security/selection-privacy.md).

## Historical Wiki request-flow record

The following six steps preserve the complete request-flow section of the
former `docs/wiki/Architecture.md` at repository snapshot
`b5def7d6156d7862606a0edcbd7226652cf4833f`. They are a **historical workflow
state of the Wiki source, not verified as current operating instructions**.
In particular, the list does not provide a command, prove that a backend or
lease is available, or turn a current offer into authorization for mutation.

1. Read current selection options instead of reconstructing a model matrix.
2. Resolve the requested or default class/lifecycle/model/effort tuple once.
3. Apply authority, capability, account, and admission checks.
4. Acquire the Agentin lease and bind the assignment to its approved scope.
5. Execute through the selected backend and expose only bounded metadata.
6. Retrieve explicit reports through the redacted assignment-report boundary.

The former section also stated that recovery and reconciliation handle
interrupted local transitions but do not make missing external provider
evidence successful. That limit remains consistent with the current recovery
boundary, but it too is retained here as historical Wiki wording rather than a
claim that an end-to-end recovery path has been exercised.

## Trust model

Authority, repository binding, scope, capability, lifecycle, and fresh state
must be evaluated at the mutation boundary. A previously read selection or
status is not a reservation. Missing, stale, malformed, or unavailable
evidence must fail closed rather than becoming an implicit permission.

The source tree and local tests demonstrate checked-in contracts only. They do
not prove an external provider transaction, credential validity, a
multi-coordinator deployment, desktop acceptance, or an end-to-end recovery in
a running environment.

## Related documentation

- [Control plane](control-plane.md)
- [Resolver](resolver.md)
- [Operations runbook](operations/runbook.md)
- [Recovery](operations/recovery.md)
- [Documentation navigation](README.md)
