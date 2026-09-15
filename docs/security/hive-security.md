# The Hive Security

The Hive boundaries enforce:

- typed principal class, parent, repository, scope, capability, and lifecycle;
- fresh grant validation with nonce/replay protection;
- repository root/remote/scope verification before mutation;
- revision CAS for dispatch, workpackage, admission, and private state;
- no-follow regular-file checks, private directories, atomic replacement, and
  bounded documents;
- fail-closed behavior for missing, stale, malformed, or unavailable evidence.

Public objects omit account keys, exact scope paths, lease identifiers,
credentials, prompts, terminal output, and local absolute roots. Reports carry
only identifiers, status, correlation metadata, and a payload digest.

Gottbienen plan global work but cannot write a repository directly. Königinnen
are repository-bound. Teamleiterin-, Spezialistinnen- and Saga mutations
require explicit injected callbacks; no productive mutation is reachable from
the read-only MCP The-Hive catalog. The current logical Queen runtime is not
materialized; the emergency path returns
`queen_spawn_unavailable:hive_queen_runtime_not_materialized` rather than
simulating a spawn.

Security review must include symlink/hardlink swaps, forged principals/grants,
scope escapes, stale revisions, replayed messages, oversized JSON, and public
output leak checks.
