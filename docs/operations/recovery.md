# The Hive Recovery Boundary

Recovery is a fail-closed local reconciliation contract. It is not permission
to manually rebuild, edit, or delete fleet state, managed homes, journals,
leases, or assignment metadata.

## Checked-in evidence

The fleet recovery implementation is
[`src/the_hive/fleet_recovery.py`](../../src/the_hive/fleet_recovery.py), with
the related service in
[`src/the_hive/fleet_service.py`](../../src/the_hive/fleet_service.py). Focused
test coverage exists in
[`tests/test_fleet_recovery.py`](../../tests/test_fleet_recovery.py) and
[`tests/test_fleet_service.py`](../../tests/test_fleet_service.py).

The service source defines private fleet paths for a registry, secrets, limits,
recovery journal, locks, usage, and events. Those implementation details do
not authorize direct editing. The server's default local state-root string
retains the technical legacy name `~/.local/state/codex-master-mcp`; treat it
as a compatibility detail, never as a portable recovery command or a reason to
expose private paths.

## Safe sequence

1. Obtain authorized current, bounded status and diagnostics.
2. Verify the target identity and scope before proposing any mutation.
3. Use the product's applicable recovery or service path so its locking,
   journal, and replacement rules remain in force.
4. Reconcile only states supported by authoritative local evidence.
5. Preserve unresolved external states as blockers and, where authorized,
   repeat status plus focused checks after the recovery action.

Do not infer a successful provider-side transaction, materialized external
home, cross-store compensation, multi-coordinator behavior, or desktop result
from local recovery source or tests. Each requires its own current evidence and
authorization.

## Related documentation

- [Operations runbook](runbook.md)
- [Architecture](../architecture.md)
- [Agent pool](../agent-pool.md)
- [Hive operations](hive-operations.md)
- [Hive security](../security/hive-security.md)
