# Wiki Consolidation Record

**Migration date:** 2026-09-15
**Verified source snapshot for this parity mapping:**
`b5def7d6156d7862606a0edcbd7226652cf4833f`

For current product status, use [ROADMAP.md](../../ROADMAP.md), which is
verified against Current-Main snapshot
`4eef3d90db78f72efb96d1888d15af8c024cd5a0`.

This record closes the former `docs/wiki/` publishing layout. The normal,
versioned repository documentation under [`docs/`](../README.md) is the only
target architecture. It makes no claim that a runtime was tested or that a
GitHub Wiki was created, synchronized, or removed remotely.

The separate [active-documentation consolidation record]
(active-documentation-consolidation.md) classifies the large reductions made to
non-Wiki active documentation. It is intentionally separate from this
Wiki-source parity record.

## Section-level parity check before removal

| Former source | Former section or material | Preserved destination / decision |
|---|---|---|
| `docs/wiki/Home.md` | Reading order; normal source navigation; evidence boundary | [`docs/README.md`](../README.md) provides repository navigation and links to the five migrated topics. The former order is Architecture → Recovery → Resolver → Control plane → Runbook. The source-only-versus-runtime-evidence boundary is retained across the five destination pages. |
| `docs/wiki/Architecture.md` | Component orientation; six-step request-flow; state/trust boundaries; canonical detail links | [`docs/architecture.md`](../architecture.md): Orientation; Components and boundaries; **Historical Wiki request-flow record**; Trust model; Related documentation. The entire six-step flow is retained precisely as historical Wiki workflow state, not as a verified current operating instruction. The old `Codex Master`/`Masterjet` identity is replaced by current **The Hive** terminology. |
| `docs/wiki/Control-Plane.md` | Contract layers; fail-closed rules; operational evidence boundary; detail links | [`docs/control-plane.md`](../control-plane.md): Checked-in contract layers; Fail-closed boundary; Evidence limit; Related documentation. The former claim that admission has no numeric concurrency cap is retained as an unverified historical assertion and not promoted to a current contract. |
| `docs/wiki/Resolver.md` | Five-step selection flow; policy sources; evidence boundary | [`docs/resolver.md`](../resolver.md): Current source-backed inputs; Selection boundary; **Historical Wiki selection-flow record**; Evidence limit; Related documentation. The whole five-step flow and its visible-fallback constraint are retained as historical Wiki workflow state, not as a verified current operating instruction. Current catalog and schema paths replace former links without reproducing a live model matrix. |
| `docs/wiki/Runbook.md` | Read-only diagnosis intent; safe assignment flow; mutation boundary; publication boundary | [`docs/operations/runbook.md`](../operations/runbook.md): Start with the intended interface; Safe operational sequence; Mutation and release boundaries; Related documentation. Unverified historical command examples are not current instructions. |
| `docs/wiki/Recovery.md` | Safe sequence; locally covered behavior; local-evidence limits | [`docs/operations/recovery.md`](../operations/recovery.md): Checked-in evidence; Safe sequence; Related documentation. Current `src/the_hive/` and `tests/` paths replace obsolete `src/codex_master/` paths. |
| `docs/wiki/PUBLISHING.md` | GitHub-Wiki source-to-page mapping and remote publication, verification, and rollback procedure | **Deliberately discarded.** This was a Wiki-only publishing procedure, not product or operator guidance. Retaining it would preserve a prohibited second documentation architecture and remote-mutation instructions. No publication procedure was migrated. |

## Terminology and evidence corrections

- Active product documentation uses **The Hive**, package `the-hive`, and
  source root `src/the_hive/`. The former `Codex Master` and `Masterjet` names
  are historical names only.
- Historical paths and commands under `codex_master` and `bin/codex-master-mcp`
  were not reintroduced as current guidance. The current release wrapper is
  [`bin/the-hive-mcp`](../../bin/the-hive-mcp), which requires a release root,
  generation, and manifest digest; it is not documented as a checkout command.
- The current man-page source is
  [`man/man1/the-hive-mcp.1`](../../man/man1/the-hive-mcp.1). Its independently
  identified routing and `PYTHONPATH` inconsistencies were not propagated into
  the migrated pages.
- The technical legacy state-root string
  `~/.local/state/codex-master-mcp` remains source evidence only. It does not
  change the product identity and is not an operator-facing path instruction.

## Sources used for the migration

- [`pyproject.toml`](../../pyproject.toml) for package identity and console
  entry points.
- [`bin/the-hive-mcp`](../../bin/the-hive-mcp) for the release-wrapper argument
  contract.
- [`codex-hive.json`](../../codex-hive.json),
  [`codex-agent-classes.json`](../../codex-agent-classes.json),
  [`codex-model-policy.json`](../../codex-model-policy.json), and
  [`codex-agent-pool.json`](../../codex-agent-pool.json) for checked-in
  configuration inputs.
- [`src/the_hive/`](../../src/the_hive/),
  [`tests/test_fleet_recovery.py`](../../tests/test_fleet_recovery.py), and
  [`tests/test_fleet_service.py`](../../tests/test_fleet_service.py) for current
  module and test paths.
