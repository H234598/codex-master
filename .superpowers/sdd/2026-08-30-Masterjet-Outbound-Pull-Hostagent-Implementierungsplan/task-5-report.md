# Task 5 report — fix round 4/5

## Verdict

The one Important finding from `task-5-rereview-3.md` is addressed, and all
five findings from `task-5-rereview-2.md` remain closed. No Task 6 work was
started.

Recovered runtime adoption now accepts only a correctly named executable memfd
whose exact open descriptor carries all four immutable launcher seals and
matches the planned size and digest. A mutable same-name memfd cannot enter or
reuse the executable-identity cache.

## Exact tracked scope

- `src/codex_master/ollama_runtime.py`
- `tests/test_ollama_runtime.py`
- `task-5-implementation.md`, `task-5-report.md`, and `progress.md` under the
  existing Task-5 SDD report directory

No other production/test file, credential name, Task-6 API, systemd unit,
listener, fleet/UI file or 30-second lease-cap behavior was changed.

## Root cause and correction

The old adoption cache treated `(pid, start_ticks, inode, expected_digest)` as
proof that executable content remained stable. An attacker-controlled memfd
could use the trusted name, match once, then be overwritten without changing
those fields. The stale entry therefore remained authoritative.

The evidence check now obtains one descriptor for `/proc/<pid>/exe`, validates
the descriptor target, requires `F_SEAL_SEAL`, `F_SEAL_SHRINK`, `F_SEAL_GROW`
and `F_SEAL_WRITE`, and derives device/inode/size/hash/cache identity only from
that held descriptor. It closes the descriptor on every return. Cache lookup
and insertion occur only after seal verification; insertion additionally
requires an exact bounded digest match. Existing final process and cgroup
identity rechecks remain in place.

## TDD evidence

- Real unsealed memfd RED: `1 failed`; initial and cached checks were both
  incorrectly `True`, and a full live overwrite succeeded with zero seals.
- Real unsealed memfd GREEN: rejected before and after the overwrite.
- Real launcher-sealed memfd GREEN: initial Evidence SHA-256 verification and
  a later cache hit both accepted.

## Verification

- Minimal live-kernel checks: `2 passed in 0.48s`.
- Full runtime module: `66 passed in 2.96s`.
- Focused Task 5/runtime: `127 passed in 21.92s`.
- Direct runtime-consumer regressions: `195 passed in 3.48s`.
- CodeRabbit uncommitted round 1: 0 findings in both changed Python files.
- Ruff: PASS.
- Compileall: PASS.
- `git diff --check`: PASS.
- Secret scan: PASS, no matches.

## Deliberate fail-closed decisions

- Procfs exposes `exe` as a kernel magic link, so it must be resolved once to
  acquire the executable backing descriptor. All security decisions then use
  only that single held descriptor; there are no separate target `stat` or
  content opens.
- Failure to query seals, any missing seal, an unexpected target, an oversized
  body or a digest mismatch all fail closed and do not populate the cache.
- The persisted monotonic duration remains capped at the explicit 30-second
  Master lease maximum; this round did not alter lease handling.

## Remaining rollout gate

The installed Ollama/systemd E2E and fixed credential provisioning remain
Task-9/later integration work. Seal verification is Linux/procfs-specific, as
is the existing production runtime. Runtime private seals remain process-local
and are never persisted or forged.
