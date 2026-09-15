# The Hive Roadmap

Status is intentionally separated into source-integrated work, prepared work,
blockers, and later work. It is based on repository snapshot
`b5def7d6156d7862606a0edcbd7226652cf4833f`; it makes no live-runtime,
provider, approval, deployment, or CI-success claim.

This documentation candidate remains on b5. At the check time, `origin/main`
is one commit ahead at `a65fe3972f7859e808ec6f09a39808fa240d4f49`
(`feat(hive): add BUS-S1 slice A store foundation`), which adds a BUS-S1 store
module and its focused test. BUS-S1 is therefore not claimed as integrated in
this candidate; its product and status impact has not been assessed here.

## Now — integrated in the repository

- **The Hive package and runtime entrypoints.** The package metadata exposes
  The Hive entrypoints, and [`.mcp.json`](.mcp.json) selects the attested stable
  MCP launcher. The stable launcher and the three-argument runtime wrapper
  are present in [`bin/`](bin/). Evidence: [pyproject.toml](pyproject.toml),
  [`.mcp.json`](.mcp.json), [`bin/the-hive-mcp-stable`](bin/the-hive-mcp-stable),
  and [`bin/the-hive-mcp`](bin/the-hive-mcp).
- **Bounded Hive control-plane source.** Typed principals, repository
  bindings, grants, work packages, admission, queues, and event records are
  implemented as source contracts. Evidence: [src/the_hive/hive/](src/the_hive/hive/)
  and the associated `tests/test_hive_*.py` files.
- **DiagnosticV2 P0.** Commit
  `b5def7d6156d7862606a0edcbd7226652cf4833f` adds the canonical, redacted
  `DiagnosticV2` value and wire contract with focused tests. Evidence:
  [src/the_hive/diagnostics.py](src/the_hive/diagnostics.py) and
  [tests/test_diagnostics.py](tests/test_diagnostics.py). No deployment or
  downstream adoption beyond the source contract is inferred.
- **BUS-S0 contract.** Commit `02613e7` adds the bounded BUS-S0 type contract;
  commit `68450b6` normalizes its file endings. Evidence:
  [src/the_hive/hive/bus_types.py](src/the_hive/hive/bus_types.py) and
  [tests/test_hive_bus_types.py](tests/test_hive_bus_types.py). This is a
  static contract, not evidence of a running bus broker or transport.

## Next — prepared, but not active by this repository alone

- **Fail-closed admission execution.** The runtime adapter has a fixed gate
  order and needs an injected executor; a missing gate, stale evidence, or
  missing callback denies execution. The server factory is explicitly not
  called by an MCP tool. Evidence:
  [src/the_hive/admission_runtime.py](src/the_hive/admission_runtime.py) and
  [src/the_hive/server.py](src/the_hive/server.py).
- **Reversible local pilot provisioning.** The pilot provisioner can plan,
  apply, verify, kill-switch, and roll back a narrowly defined pilot. This is
  implementation readiness, not proof that a pilot is approved or currently
  running on any host. Evidence:
  [src/the_hive/hive/pilot_provisioner.py](src/the_hive/hive/pilot_provisioner.py)
  and [docs/operations/hive-pilot-provisioner.md](docs/operations/hive-pilot-provisioner.md).
- **Explicit multi-repository saga boundary.** The source accepts work only
  when pilot allowlists, confirmed user gates, and create/execute/compensate
  callbacks are supplied. Evidence:
  [src/the_hive/hive/dispatch.py](src/the_hive/hive/dispatch.py). It is not a
  hidden, globally atomic execution path.

## Blocked — external evidence or unfinished runtime work required

- **Logical Queen runtime.** The documented controller returns
  `queen_spawn_unavailable:hive_queen_runtime_not_materialized`; it does not
  pretend to have started a Queen. Evidence:
  [docs/operations/hive-operations.md](docs/operations/hive-operations.md).
- **Provider use and operational approval.** Credentials, provider reachability,
  current resource/account/lease/auth/config gates, pilot approval, and
  operator acceptance are external runtime facts. They require fresh
  evidence, not only this checkout. Evidence:
  [src/the_hive/admission_runtime.py](src/the_hive/admission_runtime.py) and
  [docs/security/hive-security.md](docs/security/hive-security.md).
- **CI manifest identity conflict.** The checked-in plugin and app manifests
  use The Hive keys, while [`.github/workflows/ci.yml`](.github/workflows/ci.yml)
  still asserts the historical `codex-master` plugin name and app key. Until
  that contradiction is corrected and a run is independently verified, CI is
  a blocker and not a success signal.

## Later — planned, not integrated

- **CourseGuard.** It is a planned item for this documentation programme, not
  an integrated product capability. No matching CourseGuard source, test, or
  current product-documentation artifact was found in this snapshot; no
  behavior or delivery date is inferred.

## Reading this roadmap

For product and operator navigation, use [docs/README.md](docs/README.md).
Historical plans, templates, and handoffs are working material, not evidence
that a feature has been integrated or activated.
