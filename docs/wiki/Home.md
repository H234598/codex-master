# Codex Master Wiki Sources

> Canonical repository source: `docs/wiki/Home.md`  
> Last verified: 2026-08-14 against the local source tree  
> Publication status: local source; not yet published to GitHub Wiki

These pages are the versioned source for a future GitHub Wiki. The repository
copy remains canonical after publication. Wiki publication must copy from these
files and must not become a second policy source.

## Reading order

1. [Architecture](Architecture.md) — components, state, and trust boundaries.
2. [Recovery](Recovery.md) — local recovery contract and external limits.
3. [Resolver](Resolver.md) — central selection flow and canonical policy links.
4. [Control Plane](Control-Plane.md) — authority, admission, and assignment.
5. [Runbook](Runbook.md) — safe diagnosis and delegated operations.

## Canonical references

- [Project README](../../README.md)
- [Agentinnen pool](../agent-pool.md)
- [Selection operations](../operations/selection-operations.md)
- [Hive operations](../operations/hive-operations.md)
- [`codex-master-mcp(1)` source](../../man/man1/codex-master-mcp.1)

## Evidence boundary

The pages distinguish checked-in local contracts from productive evidence.
Local tests do not prove provider availability, external materialization,
multi-Queen pilots, desktop acceptance, or an enabled control plane. Operators
must query current status before acting.
