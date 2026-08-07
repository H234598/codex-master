# Hive/Selection Migration

Migration is additive and reversible:

1. validate config and schemas;
2. run read-only Hive and Selection diagnostics;
3. compare legacy assignment metadata with Hive metadata when both sides exist;
4. use Shadow previews without Admission, Lease, Fairness, or Lifecycle writes;
5. enable only explicitly allowlisted feature flags;
6. reconcile or roll back metadata without deleting pool homes or state files.

Missing comparison sides are reported as non-comparable, not as success.
Rollback is a dry-run/status operation unless a separately authorized mutation
path is supplied. It never removes state files, copies credentials, changes
Agentin homes, or publishes a release.

Before any Enforced rollout, verify fresh authority, repository, scope,
account, model, usage, lease, process, auth, and config evidence. A cached
plugin inventory or a green local preview is not external pilot or provider
evidence.
