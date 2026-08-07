# Selection Operations

Selection is a preview/ordering layer. It does not start, stop, interrupt,
reserve, or preempt an Agentin.

Run a bounded preview from the server:

```sh
python3 -m codex_master.server selection-preview \
  --series d --task-kind simple --admission-mode shadow --limit 8
```

Selection evaluates eligibility first, then assigns a band and deterministic
tie-break key. A candidate that is ineligible never receives a selection band.
The fairness ledger is immutable during preview. Final execution must create a
fresh admission and revalidate every server/Hive gate immediately before the
existing low-level assignment operation.

Safe rollout order is SP3, SP2, SP1, then passive SP0. Feature policy is a
fail-closed upper bound: a caller cannot enable a flag that the loaded policy
does not allow. A disabled feature produces a reason code and no state write.

For current usage, prefer the typed Usage-v2 source. A missing, stale,
unverified, or semantically ambiguous source is reported as unavailable; the
system never infers a reset or quota from free-form provider text.
