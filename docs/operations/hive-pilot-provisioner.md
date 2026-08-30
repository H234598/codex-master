# Local Hive Enforced-Pilot Provisioner

The only tracked administrative path for the local Hive Enforced-Pilot is
`scripts/codex-master-hive-pilot-provisioner`. Do not edit `codex-hive.json`,
`principals.json`, or the provisioner journal manually.

The command is intentionally separate from the read-only MCP/CLI status
surface. It has no installer, reload, service, account, provider, or spawn
operation. `status` and `doctor` remain projections of the existing
authoritative Hive runtime assembler.

First produce a non-mutating plan. Both roots must be absolute, direct,
user-owned paths; the repository must be the canonical `codex-master` Origin
on `main`.

```sh
./scripts/codex-master-hive-pilot-provisioner plan \
  --repository-root /absolute/path/to/codex-master \
  --state-root /absolute/private/hive-state
```

After the plan is reviewed, the same single command may be called with the
explicit confirmation flag:

```sh
./scripts/codex-master-hive-pilot-provisioner apply --confirm \
  --repository-root /absolute/path/to/codex-master \
  --state-root /absolute/private/hive-state
```

`apply` accepts only the canonical empty Shadow baseline. It first writes the
bounded no-follow private Principal state, journals `prepared`, and then
atomically replaces the public config with exactly one binding:
`codex-master` / `https://github.com/H234598/codex-master.git` / `main` and
the two Principals `godbee-main`, `queen-codex-master`. All SP flags are
explicitly `false`. A crash before the config rename leaves Shadow active; a
subsequent identical `apply --confirm` resumes only that prepared transition.

Inspect parity without mutation:

```sh
./scripts/codex-master-hive-pilot-provisioner verify \
  --repository-root /absolute/path/to/codex-master \
  --state-root /absolute/private/hive-state
```

The pilot is still fail-closed until the existing `codex-usage` V2 reader
verifies a fresh, long-lived `main`-pool record for the Queen's configured
`sol/max` capability. That reader validates its active source/producer/release
binding, generation, observation time and fixed 15-minute TTL before the Hive
gate sees it. Caller-provided mappings, unverified sources or issuers, and
stale records are rejected; this command neither creates nor stores a second
attestation truth. Therefore a configured pilot may correctly report
`authority: fail_closed` and `pilot: blocked` until the canonical pool record
exists.

The kill-switch moves the config atomically back to the canonical empty Shadow
state before any cleanup. It leaves the private initial state intact for
forensics and makes the runtime fail closed immediately:

```sh
./scripts/codex-master-hive-pilot-provisioner kill-switch --confirm \
  --repository-root /absolute/path/to/codex-master \
  --state-root /absolute/private/hive-state
```

Rollback is the second, recoverable step: it requires the same journal/config
identity, preserves Shadow first, and then removes only the validated initial
`principals.json` file.

```sh
./scripts/codex-master-hive-pilot-provisioner rollback --confirm \
  --repository-root /absolute/path/to/codex-master \
  --state-root /absolute/private/hive-state
```

All results are redacted. Symlinks, parent/config swaps, unexpected owner,
mode, type, link-count, size, repository, Principal, journal, config, and
state drift are rejected rather than repaired. Repeating an already committed
`apply` is a no-op; replaying a drifted input is rejected.
