# D378-B – isolated runtime Canary handoff

Status: `WORKER_COMPLETE_AWAITING_TL_REVIEW`
Date: 2026-09-28 (Europe/Berlin)
Branch: `d378b-flex-watchdog`
Reviewed parent / starting HEAD: `ea83d5903cab77c118de005f23e29ac8fa2804c4`
Canary follow-up parent: `76ab518f33494d2850d30dd0aa25b8af7fb2b9bd`

## Scope

This change adds the missing public, bounded diagnostic route:

```text
./scripts/the-hive-runtime-service canary --home <absolute-home>
```

It does not change the canonical cutover, installed runtime, pointers, user
units, timers, pricing inventory, health, or migration policy. It does not
claim a root cause or a remediation for the live `command_group_unavailable`
failure.

Tracked files in this handoff:

- `src/the_hive/runtime_lifecycle.py`
- `tests/test_runtime_lifecycle_service.py`
- `.local/d378b-flex-watchdog-openai-tl-handoff.md`

The pre-existing untracked prompt files remain excluded and untouched:

- `.local/d378b-flex-watchdog-openai-fix5.prompt.md`
- `.local/d378b-flex-watchdog-openai-review-fix4.prompt.md`

## Closed source gap

Before this change, the public lifecycle exposed only `cutover`, `status`, and
`verify`. The installer stage validator was not a Canary: it did not run the
exact Hourly systemd sandbox and entered the canonical publisher transaction.
Manual pointer, unit, launcher, or manager composition was forbidden.

The new command is a separate diagnostic authority with no canonical runtime
authority:

1. It attests a completely clean tracked repository through the existing
   commit/tree-closure binding. Any tracked change or untracked file fails
   before the Canary root or manager is entered.
2. It holds the existing installer entry by descriptor, reuses only the
   existing complete Runtime Image builder and manifest publisher, and creates
   a private disposable release at
   `/run/user/<euid>/the-hive-runtime-canary/run-*/.local/lib/the-hive-runtime`.
   The generation is the clean source commit; the digest is the generated
   manifest digest.
3. It does not call the installer's stage validator. Its required release
   pointer and stable launcher remain below the disposable invocation root; it
   creates no canonical live pointer, unit, launcher, or pin-store authority.
4. It reads the manifest-attested Hourly service, preserves every static
   service directive, and transforms only the typed RuntimeDirectory,
   release/state bind sources, and ExecStart binding. The unique manager-owned
   Canary RuntimeDirectory is bridged read-only to the fixed
   `%t/the-hive-hourly-runtime` path accepted by `runtime_process`; the public
   manager bus remains bound only below that fixed path. Unknown or duplicate
   path/ExecStart directives fail closed.
5. It starts exactly one random 128-bit-named transient user service via
   `systemd-run --no-block`. The unit uses the canonical `107s` service bound;
   lifecycle polling is bounded to `112s`, and manager entry is bounded to
   `15s`.
6. The disposable release and empty private state are bind sources. Their
   sandbox destinations remain the canonical Hourly paths, so the executed
   program sees the production layout without reading or changing the host's
   canonical release, state, health, pricing, launcher, units, or timers.
7. Caller environment is excluded from both manager adapters. The transient
   unit receives explicit `HOME`, `LANG`, and `PATH` overrides; the existing
   attested launcher retains its own CODEX/Python sanitization. Its explicit
   working directory remains the supplied Home, matching the user-unit default
   and introducing no new CWD contract. Service stdout/stderr are `null`; no
   raw child output is returned.
8. Before start, the random unit name must be `not-found`. After start,
   `Transient=yes` and the exact random Description attest ownership. A foreign
   unit is never stopped or reset.
9. `finally` re-attests exact current transient ownership immediately before
   both `stop` and conditional `reset-failed`; historical ownership never
   authorizes a mutation. A failed, empty, or foreign current show stops
   cleanup fail-closed. It then proves final `LoadState=not-found` and removes
   the complete invocation root. Any manager or filesystem cleanup uncertainty
   replaces the diagnosis with `runtime_canary_cleanup_unverified`.

The coordination root and its private lock may persist under the UID runtime
directory. No generation, state record, process, or transient unit is retained.

## Public evidence contract

Every result contains only:

- `status`
- `error_code`
- `generation`
- `manifest_digest`
- `raw_output=not_returned`

Accepted diagnostic outcomes are deliberately narrow:

- `runtime_canary_green` with `error_code=null`; or
- `runtime_canary_red` with exactly one of the six reviewed `ea83d590` codes:
  - `command_runtime_directory_unavailable`
  - `command_spawn_helper_unavailable`
  - `command_cgroup_preflight_unavailable`
  - `command_manager_preflight_unavailable`
  - `command_native_spawn_unavailable`
  - `command_cgroup_bind_unavailable`

Missing, malformed, contradictory, unknown, or freely worded diagnostic data
becomes `runtime_canary_evidence_invalid`. Exception text, paths, environment,
stderr, stdout, and tokens are never returned.

## Manager-free evidence

No test in this task contacted the user manager. `systemctl` and `systemd-run`
were fully mocked; the one real image test only built and attested a disposable
filesystem image below pytest's temporary directory.

Passed before final commit:

```text
# Red regression before the follow-up production fix:
PYTHONPATH=src pytest -q \
  tests/test_runtime_lifecycle_service.py::test_canary_runtime_directory_reaches_the_fixed_runtime_process_contract \
  tests/test_runtime_lifecycle_service.py::test_canary_cleanup_never_uses_historical_ownership_after_show_failure \
  tests/test_runtime_lifecycle_service.py::test_canary_cleanup_rejects_foreign_replacement_between_stop_and_reset
# 2 failed, 1 passed

python3 -m py_compile \
  src/the_hive/runtime_lifecycle.py \
  src/the_hive/runtime_process.py \
  tests/test_runtime_lifecycle_service.py

PYTHONPATH=src pytest -q tests/test_runtime_lifecycle_service.py \
  -k 'canary or public_runtime_lifecycle_surface'
# 28 passed, 281 deselected

PYTHONPATH=src pytest -q tests/test_runtime_lifecycle_service.py
# 309 passed in 9.60s

git diff --check
```

The focused evidence covers:

- clean commit/tree closure and rejection of an untracked source;
- complete manifest generation, commit identity, and digest binding;
- byte-structural Hourly sandbox parity and rejection of extra/changed bind or
  ExecStart directives;
- isolated release/state sources and unchanged canonical pointer, health,
  pricing, and unit sentinels;
- safe unique unit and RuntimeDirectory names;
- two distinct unique RuntimeDirectory sources reaching the fixed
  cross-module `runtime_process` destination without a `/tmp` bridge;
- explicit manager/service/poll bounds and exactly one start attempt;
- all six `ea83d590` pre-exec stage codes;
- green evidence and unknown evidence fail-closed;
- cleanup after a start adapter error;
- individual `stop`, `reset-failed`, and filesystem cleanup failures;
- refusal to mutate after a current-show failure and refusal to reset a unit
  replaced between `stop` and `reset-failed`;
- concurrent invocation rejection;
- foreign-unit rejection without mutation; and
- caller-environment exclusion and raw-output redaction.

## Mutations deliberately not performed

- no fetch, push, merge, rebase, or integration;
- no canonical cutover or installer invocation;
- no real `systemctl`, `systemd-run`, daemon reload, unit start, or transient
  unit;
- no pointer, pin-store, launcher, unit, timer, pricing, or health mutation;
- no live Canary execution; and
- no deletion or staging of the two excluded prompt files.

## Gate separation and residual work

The diagnostic gate and remediation gate are separate.

This source makes a future, explicitly authorized live Canary possible from a
clean detached source. It does not prove which stage will fail live. The live
root cause therefore remains unknown until that one bounded Canary is reviewed,
integrated, and separately authorized to run.

Even after a live stage code exists, no cutover retry is authorized by this
handoff. A red regression, minimal remediation, focused tests, and independent
TL review remain required before integration. The runtime migration-policy
package is still outstanding and is not implied or modified by this diagnostic
route.
