# Recovery

> Canonical repository source: `docs/wiki/Recovery.md`  
> Last verified: 2026-08-14 against the local source tree  
> Publication status: local source; not yet published to GitHub Wiki

Recovery protects registry, private state, homes, and assignment metadata from
partially completed local transitions. It is a fail-closed reconciliation
contract, not permission to rebuild or delete fleet state manually.

## Safe sequence

1. Observe current registry generation, Agentin status, leases, and diagnostics.
2. Validate target identity and scope before any mutation.
3. Use the repository recovery/service path so locking, journal, intent, and
   atomic replacement rules remain active.
4. Reconcile only states supported by authoritative local evidence.
5. Re-run status and targeted tests; preserve unresolved external states as
   blockers rather than guessing success.

Direct edits to managed homes, private state, journals, or lease records bypass
these contracts and are not a recovery procedure.

## Locally covered behavior

The repository contains registry, service, in-place, journal, locking, and
fresh-process/crashpoint tests. These provide local evidence for checked-in
contracts and selected restart boundaries.

- [Agentinnen pool operations](../agent-pool.md)
- [Hive runtime assembly and recovery](../operations/hive-operations.md#runtime-assembly-and-recovery)
- [Fleet recovery implementation](../../src/codex_master/fleet_recovery.py)
- [Fleet recovery tests](../../tests/test_fleet_recovery.py)
- [Fleet service tests](../../tests/test_fleet_service.py)

## Not proved by local recovery

- provider-side transactions or credential validity;
- physical home/provider materialization outside observed local state;
- cross-store compensation after an external process crash;
- productive multi-Queen, assignment, or desktop pilots.

Those conditions require their own evidence and authorization. Do not close an
end-to-end recovery gate from local unit tests alone.
