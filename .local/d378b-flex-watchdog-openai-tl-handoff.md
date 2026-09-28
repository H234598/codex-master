# D378-B – isolated runtime Canary handoff

Status: `WORKER_COMPLETE_AWAITING_TL_REVIEW`
Date: 2026-09-28 (Europe/Berlin)
Branch: `d378b-flex-watchdog`
Reviewed parent / starting HEAD: `ea83d5903cab77c118de005f23e29ac8fa2804c4`
Canary follow-up parent: `76ab518f33494d2850d30dd0aa25b8af7fb2b9bd`
Manager-adapter follow-up parent: `e7520ef7850f28d6356d83e9ecc87dbd9e14303e`

## Scope

This change adds the missing public, bounded diagnostic route:

```text
./scripts/the-hive-runtime-service canary --home <absolute-home>
```

It does not change the canonical cutover, installed runtime, pointers, user
units, timers, pricing inventory, health, or migration policy. It does not
claim a root cause or a remediation for the live `command_group_unavailable`
failure.

## Historical live evidence binding this follow-up

The one separately authorized live Canary from generation
`e7520ef7850f28d6356d83e9ecc87dbd9e14303e` exited 1 and returned only:

- `status=runtime_canary_failed`;
- `error_code=runtime_canary_manager_failed`;
- manifest digest reported as the bounded prefix `sha256:f152…` (the full
  digest was not supplied to this follow-up and remains unknown); and
- `raw_output=not_returned`.

Post-run evidence found zero Canary run roots, zero Canary units, zero jobs,
and only the coordination `.canary.lock`. No Canary/systemd-run journal
metadata survived. The previous adapter collapsed every synchronous nonzero
`systemd-run` result and discarded stderr, so the exact manager subpath cannot
be reconstructed. The product root cause therefore remains unknown.

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
10. A synchronous `systemd-run` exit is classified only when exit status is
    exactly 1, stdout is empty, and stderr is one exact installed systemd-259.9
    `LANG=C` full line. The fixed classes distinguish transient-service
    `Invalid argument`, user-bus absence/refusal, and manager `Access denied`.
    Extra, multiple, oversized, dynamic, or unknown output remains
    `runtime_canary_manager_failed`; OSError and timeout remain
    `runtime_canary_manager_unavailable`. No raw text enters an exception or
    public result, and the adapter still performs exactly one start attempt.

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

Before command execution, an exact synchronous manager failure may instead
return `runtime_canary_failed` with one of these bounded codes:

- `runtime_canary_manager_contract_invalid`;
- `runtime_canary_manager_unavailable`;
- `runtime_canary_manager_rejected`; or
- the generic `runtime_canary_manager_failed` for every unrecognized form.

Cleanup uncertainty still replaces any of these with
`runtime_canary_cleanup_unverified`.

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

# Red manager-adapter regression before its production fix:
PYTHONPATH=src pytest -q tests/test_runtime_lifecycle_service.py \
  -k 'systemd_run_default or fixed_manager_start_code or cleanup_failure_overrides_fixed_manager_start_code'
# 6 failed, 8 passed, 308 deselected

# Red exception-chain redaction before its adapter fix:
PYTHONPATH=src pytest -q tests/test_runtime_lifecycle_service.py \
  -k 'systemd_run_default_os_and_timeout_failures_remain_unavailable'
# 2 failed, 323 deselected

python3 -m py_compile \
  src/the_hive/runtime_lifecycle.py \
  tests/test_runtime_lifecycle_service.py

PYTHONPATH=src pytest -q tests/test_runtime_lifecycle_service.py \
  -k 'canary or public_runtime_lifecycle_surface'
# 36 passed, 289 deselected

PYTHONPATH=src pytest -q tests/test_runtime_lifecycle_service.py \
  -k 'systemd_run_default or fixed_manager_start_code or cleanup_failure_overrides_fixed_manager_start_code'
# 17 passed, 308 deselected

PYTHONPATH=src pytest -q tests/test_runtime_lifecycle_service.py
# 325 passed in 9.60s

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
- caller-environment exclusion and raw-output redaction;
- exact installed manager-error classification with one start attempt;
- collapse of secret-bearing, multi-line, contradictory, oversized, or
  unexpected-exit output to the generic fixed code;
- unchanged OSError/timeout unavailability without a foreign exception cause
  or context; and
- public propagation of fixed manager codes with cleanup precedence.

## Mutations deliberately not performed

- no fetch, push, merge, rebase, or integration;
- no canonical cutover or installer invocation;
- no real `systemctl`, `systemd-run`, daemon reload, unit start, or transient
  unit;
- no pointer, pin-store, launcher, unit, timer, pricing, or health mutation;
- no live Canary execution;
- no retry or diagnostic systemd-run invocation for the historical live
  failure; and
- no deletion or staging of the two excluded prompt files.

## Gate separation and residual work

The diagnostic gate and remediation gate are separate.

This source makes a future, explicitly authorized live Canary able to preserve
one bounded manager sub-class without returning raw output. It does not prove
which manager form occurred historically and does not prove which stage will
fail in a future run. The live root cause remains unknown until this follow-up
is independently reviewed, integrated, and a new bounded Canary is separately
authorized.

Even after a live stage code exists, no cutover retry is authorized by this
handoff. A red regression, minimal remediation, focused tests, and independent
TL review remain required before integration. The runtime migration-policy
package is still outstanding and is not implied or modified by this diagnostic
route.
