# Task 5 fix round 1 implementation evidence

## Result

All 3 Critical and 7 Important findings from `task-5-review.md` are fixed
within the seven-file Task 5 scope. No Task 1–4 production file, systemd unit,
master listener, fleet/UI code, or unrelated runtime code was changed.

## TDD and remediation evidence

- Atomic durable mutation claims are serialized by `HiveStateStore`; concurrent
  executors wait and re-read until the winning claim is terminal or can be
  durably recovered as `unknown`. The concurrency test observes one runtime
  effect and two identical receipts.
- `apply`/`stop` exceptions after the claim produce `unknown` with
  `host.operation_unknown`. Only `AgentOllamaNoEffectError`, the typed proof
  that no effect occurred, produces `failed`.
- All HTTP redirects (301/302/303/307/308) are rejected. Live TLS tests cover
  same- and cross-origin redirects and prove that no second mTLS server is
  contacted.
- Replay records bind operation ID, lease ID, attempt, host, kind, action,
  registry generation, lease epoch, plan digest, and arguments digest. Changed
  authoritative fields conflict; identical redelivery returns the saved
  receipt without another effect.
- `ProductionAgentOllamaAdapter` uses the existing public
  `probe_ollama_host`, `plan_local_instance`, `start_local_instance`,
  `probe_instance_readiness`, and `stop_local_instance` APIs. A real registry
  test and an executable-replacement race test prove descriptor/evidence
  revalidation at the consumer boundary.
- The CLI now opens fixed systemd credential names descriptor-first with
  `O_NOFOLLOW`, regular-file/owner/link/mode/size checks; strictly parses a
  bounded duplicate-key-free config; builds state, TLS client, registry,
  adapter and executor; and runs an interruptible poll loop. Secret values and
  paths are not accepted through argv.
- Journal schema v2 strictly validates duplicate keys, record keys/IDs,
  complete fences, receipts, host binding, bounded integers and explicit lease
  epoch/registry generation high-water marks.
- Accepted and terminal collections are both capped at 1024 on load and write.
  Expired unclaimed records are safely reclaimed; abandoned claimed records
  become terminal `unknown`. Pruning sorts candidates once and only removes
  receipts from strictly older registry generations.
- Responses require exactly one raw `Content-Type: application/json`, exactly
  one bounded decimal `Content-Length`, exact body length, strict UTF-8 JSON,
  and no duplicate JSON keys/non-finite values. Live TLS tests reject
  parameterized/duplicate content types, conflicting lengths, duplicate JSON,
  and truncation.
- The unused lexical path gate was removed. Path safety is supplied by the
  existing Ollama plan/evidence APIs and their no-follow/owner revalidation.

Observed RED evidence included the original three collection errors and, in
this round, failing tests for atomic claims, complete fences, strict state
loading, live redirect/framing behavior, the absent production adapter, the
consumer race, and typed no-effect classification before each implementation.

## Final gates

- Focused Task 5: `40 passed in 19.08s`.
- Relevant direct Task 1–4/Ollama regression slice: `184 passed in 84.90s`.
- Ruff over all six Task 5 Python files: PASS.
- `compileall` over all six Task 5 Python files: PASS.
- `git diff --check`: PASS.
- Added-line secret-pattern scan: PASS (no matches).

## Residual risks

- A live deployment still depends on correct systemd provisioning of the four
  fixed credentials and on a valid production Ollama registry; Task 9 owns the
  unit/installer provisioning.
- A real Ollama process/systemd deployment E2E remains a later integration
  gate. Runtime failures after a durable mutation claim intentionally remain
  conservative `unknown` rather than risking a duplicate effect.

## Fixrunde 2/5 — restart safety and bounded liveness

All seven Important findings from `task-5-rereview-1.md` and M1–M3 are
addressed. The tracked scope was surgically extended by exactly
`src/codex_master/ollama_runtime.py` and `tests/test_ollama_runtime.py` because
restart-safe running ownership cannot safely be recovered outside the module
that owns the private runtime seals.

- Expired, unclaimed same-operation records can atomically rebind only
  `lease_id` and a strictly increasing `attempt`; operation, host, kind,
  action, generation, epoch, plan digest and argument digest must remain
  identical. Claimed and terminal records never rebind.
- Recovery waits are interruptible and bounded by the lease deadline. A live
  thread or process that outlives the deadline produces one durable `unknown`;
  late completion replays that terminal receipt without overwrite.
- Closed action/argument validation occurs before durable acceptance. Invalid
  payloads leave no accepted record and become stable `HostAgentError`s at the
  service boundary.
- The poll loop continues after expected host/client errors, uses an
  interruptible bounded delay, and propagates fatal exceptions. Client
  transport backoff observes the same shutdown event.
- The Ollama adapter journal is private, exact and bounded by 1024 plans and
  1 MiB. It enforces deterministic age/generation expiry and cross-process
  starting claims. It persists only semantic/evidence digests and scope
  identity—not runtime seals.
- Apply reconstructs a fresh plan from the current registry and public
  planning API, checks the saved semantic/evidence digest, and then consumes
  it. Running ownership is recovered through the new public
  `adopt_running_instance()` API, which revalidates paths, unit, PID,
  start-ticks, cgroup and listener before internally creating a sealed running
  object. Concurrent distinct plans cannot start the same instance.
- Every `Transfer-Encoding` is rejected. Live TLS tests cover chunked,
  duplicate TE, TE+CL, comma lengths, EOF/truncation and surplus/pipelined
  bytes. Requests explicitly close the connection so exact raw-body reads can
  detect surplus bytes.
- M1 uses the actual live same-origin redirect target; M2 chmods the corrupt
  state fixture to `0600`; M3 performs all typed no-effect checks before
  consuming a plan.

CodeRabbit uncommitted review round 1 returned two valid adapter findings;
round 2 returned three valid concurrency/cleanup findings. All five were
independently verified and fixed: stopped-entry identity, dead starting-claim
expiry, post-start cleanup, dead running-owner reaping, and different-plan
same-instance exclusion. Round 3 returned zero findings.

Fresh final evidence:

- Focused Task 5 plus required runtime scope: `120 passed in 20.22s`.
- Relevant Task 1–4/Ollama regression slice: `185 passed in 74.61s`.
- Ruff, compileall and `git diff --check`: PASS.
- Secret-pattern scan: PASS, no matches.

## Fixrunde 3/5 — lifecycle race closure

All five Important findings from `task-5-rereview-2.md` are addressed without
transitioning to Task 6.

- Schema-3 host records persist a boot ID plus a capped monotonic deadline.
  UTC is consulted once at acceptance; waits, expiry and rebind use only the
  monotonic clock. Claimed records become conservative `unknown` after boot
  change. Schema-2 records migrate atomically under the state lock.
- Before `start_scope`, the adapter durably stores a stable random unit name,
  preallocated port, semantic/evidence digest and live owner claim. A hard
  crash is reconciled through that exact intent: exact ownership is adopted,
  proven absence is safely retried, and conflict remains unresolved and blocks
  every new start for the instance.
- Runtime start failures carry an explicit `cleanup_proven` bit. Only an exact
  bounded cleanup or proven absence releases the intent; ambiguous failures
  keep it durable. No runtime seal is serialized or forged.
- Running reconciliation classifies identity as exact, absent or conflict.
  It uses the current registry generation and accepts generation advance only
  when the fresh semantic/evidence digest is identical. Only proven unit
  absence is compare-deleted; PID/cgroup/listener/path conflicts fail closed.
- Stop transitions running ownership to a durable cross-process `stopping`
  claim before adoption or mutation. Live competitors perform no runtime
  effect. Dead-owner recovery adopts exact identity, while post-stop absence
  completes idempotently without a second stop. Ambiguous stop failures retain
  the unresolved claim.
- System adoption binds unit, PID, start ticks, cgroup, listener and the actual
  bounded `/proc/<pid>/exe` content to the planned executable digest, followed
  by a final scope identity check before a running seal is minted. Successful
  hashes use a bounded 128-entry PID/start-ticks/inode/digest cache.
- Adapter journal schema 2 safely migrates old ready plans and running records.
  An old `starting` record without stable unit identity fails closed rather
  than being discarded and risking a duplicate process.

TDD covers hard crash after start, exact intent recovery, absence/conflict and
generation reconciliation, foreign executable and PID-reuse adoption,
thread/process stop competition, UTC jumps, shutdown and late finish.

CodeRabbit ran twelve uncommitted rounds. Valid follow-up findings were fixed;
unsafe suggestions that would discard ambiguous intents/stops or remove the
explicit 30-second protocol cap were rejected. The final round returned zero
findings.

Fresh final evidence:

- Focused Task 5/runtime: `126 passed in 31.17s`.
- Relevant direct Task 1–4/Ollama regression slice: `186 passed in 73.12s`.
- Ruff, compileall, `git diff --check` and secret scan: PASS.

## Fixrunde 4/5 — sealed executable adoption

The single Important finding from `task-5-rereview-3.md` is closed within the
surgically limited runtime/test scope. No Task 6 work and no 30-second lease
cap change was made.

- RED used a real same-name, unsealed memfd containing `/usr/bin/sleep`. The
  process remained alive while its retained writable descriptor was
  overwritten. Before the fix the evidence check returned `(True, True)`
  before and after the stale cache hit, with `F_GET_SEALS=0`.
- `_process_executable_matches_evidence()` now opens `/proc/<pid>/exe` once
  and keeps that exact descriptor alive through target-name validation,
  `F_GET_SEALS`, `fstat`, cache lookup and bounded SHA-256 hashing. Procfs's
  executable magic link must be resolved once to obtain the backing file; no
  later operation re-resolves the target path.
- Adoption requires all launcher invariants on that descriptor:
  `F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE`. An unsealed or
  partially sealed memfd is rejected before any cache lookup or insertion.
- The cache identity now also includes the backing device and is populated
  only after a sealed descriptor's size and digest match. Descriptor closure
  is guaranteed by `finally`; positional reads avoid shared-offset races.
- The live legitimate-launcher test now proves both the initial sealed digest
  match and the subsequent cache hit. The malicious live test proves rejection
  both before and after mutation of the same inode.
- Existing final PID/start-ticks/cgroup/listener observations in adoption were
  retained unchanged. Once the four seals are observed on the held descriptor,
  executable bytes cannot change between hashing and that final observation.

Fresh verification:

- TDD RED: `1 failed`; observed `(True, True)` instead of `(False, False)`.
- Minimal live-kernel checks: `2 passed in 0.48s`.
- Full `tests/test_ollama_runtime.py`: `66 passed in 2.96s`.
- Focused Task 5/runtime: `127 passed in 21.92s`.
- Direct runtime consumers: `195 passed in 3.48s`.
- Ruff, compileall, `git diff --check`: PASS.
- Added-line secret-pattern scan: PASS, no matches.
- CodeRabbit CLI 0.7.5 uncommitted round 1: 0 findings across the two changed
  Python files. There were no review suggestions to accept or reject.

Independent committed-range review closed the executable-adoption Important
with no remaining production or test finding. Its sole documentation Minor—
machine-specific absolute paths in the newly tracked ledger—was replaced by
portable vault-relative and role-based descriptions. The follow-up absolute-
path scan, diff check, secret scan and CodeRabbit uncommitted review all passed
with zero findings.
