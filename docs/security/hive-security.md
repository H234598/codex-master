# Hive Security

Hive boundaries enforce:

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

Godbee plans global work but cannot write a repository directly. Queens are
repository-bound. Teamlead/Specialist and Saga mutations require explicit
injected callbacks; no productive mutation is reachable from the read-only MCP
Hive catalog.

Security review must include symlink/hardlink swaps, forged principals/grants,
scope escapes, stale revisions, replayed messages, oversized JSON, and public
output leak checks.
