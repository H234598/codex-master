# SDD ledger — plan: `Projekte/codex-master/Baupläne!/2026-08-30-Masterjet-Outbound-Pull-Hostagent-Implementierungsplan.md`

## Workspace

- Master workspace: isolated SSD-backed `codex-master` worktree
- Master branch/base: `feat/outbound-hostagent-20260830` / `8cae63b3879e8d07b9db75c33ef80e67a4e1ed92`
- Usage workspace: isolated SSD-backed `codex-usage` worktree
- Usage branch/base: `feat/outbound-hostagent-usage-20260830` / `800b91862838c0cc3484a5e8ea8b3046f7e962fd`
- Storage write/readback: PASS, SHA-256 `c4f8b482829fa7bc7c3fa1e8f143fdb732a25d21ae93c5c9093ca32b789fa09f`
- Master baseline: 440 passed in 91.89s.
- Usage baseline: 256 passed, 1 skipped in 15.82s.
- Damaged legacy workspace remains forbidden; only freshly validated isolated storage is used.

## Preflight task self-consistency

| Task | Files/tests/code internally aligned | Finding |
|---|---|---|
| 1 | Yes | Contract DTOs, exact parser tests, Ruff and commit scope agree. |
| 2 | Yes | Queue states, cancel, lease/recovery tests and Store API agree. |
| 3 | Yes | SPKI binding, HostRegistry migration, identity tests and composition files agree. |
| 4 | Yes | Two routes, TLS listener, daemon entrypoint and focused tests agree. |
| 5 | Yes | Journal states, effect fence, executor allowlist and poll-loop tests agree. |
| 6 | Yes | Local/remote adapters, Admin/CLI/MCP surface and all named test files agree after preflight correction. |
| 7 | Yes | Master projection, Usage parser, exact reason codes and cross-repo Wire tests agree after preflight correction. |
| 8 | Yes | Local/remote split, async Ollama flow, daemon test and Usage consumer agree after preflight correction. |
| 9 | Yes | Units, credential paths, installer behavior and static/runtime tests agree. |
| 10 | Yes | E2E fixture covers identity, probe, Ollama, recovery and drain requirements. |
| 11 | Yes | Test index, focused suites, mandatory gates, review, merge and push sequence agree. |

## Preflight shared-file/interface matrix

| Tasks | Shared file or producer → consumer | Finding |
|---|---|---|
| 1 → 2 | Agent DTOs → `AgentOperationStore` | Clean; Task 2 starts after Task 1. |
| 1 → 4 | Poll/receipt parsers → Agent HTTP routes | Clean. |
| 1 → 5 | Lease/receipt DTOs → host agent journal/client | Clean. |
| 2 → 4 | `AgentOperationStore` → Agent HTTP routes | Clean. |
| 2 → 6 | `AgentOperationStore` → remote host probe | Clean. |
| 2 → 7 | `AgentOperationViewV1` → public operation projection | Clean. |
| 2 → 8 | `AgentOperationStore` → remote Ollama port | Clean. |
| 3 → 4 | `AgentPrincipalV1`/resolver → TLS listener | Clean. |
| 3 ↔ 6 | `admin_assembly.py` composition | Serialized by task order; no conflict. |
| 3 ↔ 8 | `admin_assembly.py`, `test_admin_daemon.py` | Serialized by task order; Task 8 preserves identity wiring. |
| 3 → 9 | credential binding → systemd credentials | Clean. |
| 4 ↔ 5 | `pyproject.toml`; wire protocol → client | Serialized by task order; entrypoints remain distinct. |
| 4 → 6 | Agent route/store → remote probe completion | Clean. |
| 4 → 9 | Agent API CLI → API unit | Clean. |
| 5 → 6 | executor dispatch → `host.probe collect` | Clean. |
| 5 → 8 | agent Ollama executor → remote Ollama owner | Clean. |
| 5 → 9 | host-agent CLI → host-agent unit | Clean. |
| 6 ↔ 7 | `admin_contracts.py`, `admin_service.py`, `test_admin_service.py` | Serialized; Task 7 extends Task-6 operation projection. |
| 6 ↔ 8 | `admin_service.py`, `admin_assembly.py`, `test_admin_service.py` | Serialized; Task 8 consumes probe-era composition. |
| 6 → 10 | host probe adapters/results → E2E | Clean. |
| 7 ↔ 8 | `admin_service.py`, `test_admin_service.py`; async result contract → Ollama UI | Serialized; Task 8 consumes exact Task-7 wire. |
| 7 → 10 | bounded public result → E2E assertions | Clean. |
| 8 → 10 | remote Ollama queue flow → E2E | Clean. |
| 9 → 10 | units/credentials → drain and identity E2E | Clean. |
| 1–9 → 10 | all production interfaces → integrated E2E | Clean; Task 10 starts only after Task 9 review. |
| 1–10 → 11 | production functions/tests → test index and release gates | Clean; no Evidence-Reuse for release gates. |

Preflight conflicts: none. Independent plan review corrected cancellation,
reason-code names, three task file lists and canonical HostProbe return type
before this ledger was created.

## Task status

Task 1: running — implementer Grace, RH_Privat session `01a05493-d623-7d73-99f5-954de2d068e3`, base `8cae63b3879e8d07b9db75c33ef80e67a4e1ed92`
Task 1: implementation `df398c33c696661e2c07ec64ce70be16277cc30e`, 27 passed; review running — Barbara, RH_Privat session `01a0549a-732a-7881-8182-0426705ffe7b`
Task 1: review — 0 Critical, 2 Important, 1 Minor; quality needs fixes
Task 1: minor (deferred): `.superpowers/.../task-1-report.md` was force-added although scratch and outside Task-1 commit scope
Task 1: fix round 1/5 running — resumed Grace; fix base `df398c33c696661e2c07ec64ce70be16277cc30e`
Task 1: fix round 1/5 — 2 addressed, 0 open; commit `cfcd0568376e7df4420320f2459952ce5ba72828`; 42 passed; Ruff, compileall and diff-check green
Task 1: complete — commits `8cae63b3879e8d07b9db75c33ef80e67a4e1ed92..cfcd0568376e7df4420320f2459952ce5ba72828`; scoped re-review clean; 1 deferred Minor remains for whole-branch review
Task 2: pending
Task 2: running — implementer fresh RH_Privat session `01a054a3-c948-7ae1-bdc3-d23dd04ccabe`, base `cfcd0568376e7df4420320f2459952ce5ba72828`
Task 2: implementation `da0cc05236c235617f38e207dc36a06d7ff0a9b5`; 16 passed; Ruff, compileall and diff-check green; reviewer RH_Privat session `01a054b0-bfe6-7610-85a7-c999a0bd99c3`
Task 2: review — 0 Critical, 4 Important, 0 Minor; fixes required
Task 2: fix round 1/5 running — resume implementer session `01a054a3-c948-7ae1-bdc3-d23dd04ccabe`; fix base `da0cc05236c235617f38e207dc36a06d7ff0a9b5`
Task 2: fix round 1/5 — 4 addressed, 0 open; commit `f6c55eebaca39665e777a77d9242a3845ffc8a7c`; targeted 4 passed; non-slow 19 passed, 1 deselected; Ruff, compileall and diff-check green; unchanged slow 1024-record test evidence reused from `da0cc05236c235617f38e207dc36a06d7ff0a9b5`
Task 2: complete — commits `cfcd0568376e7df4420320f2459952ce5ba72828..f6c55eebaca39665e777a77d9242a3845ffc8a7c`; scoped re-review clean; 0 deferred findings
Task 3: pending
Task 3: running — implementer fresh RH_Privat session `01a054bc-60e7-70c3-9208-9f011649f05e`, base `f6c55eebaca39665e777a77d9242a3845ffc8a7c`
Task 3: implementation `04ae9bc66f4c627d146b1fd394446028f822121a`; 121 passed, 45 deselected; Ruff, compileall and diff-check green; reviewer RH_Privat session `01a054c6-4374-7443-802b-e94e4421b604`
Task 3: review — 1 Critical, 2 Important, 0 Minor; fixes required
Task 3: fix round 1/5 running — resume implementer session `01a054bc-60e7-70c3-9208-9f011649f05e`; fix base `04ae9bc66f4c627d146b1fd394446028f822121a`
Task 3: fix round 1/5 — original 1 Critical + 2 Important addressed; commit `7bdd92613b24e0f65c0a48018a7684f6766fa51b`; 3 regression tests passed; Task-3 focus 124 passed, 45 deselected; Ruff, compileall and diff-check green
Task 3: scoped re-review round 1 — original findings closed; 0 Critical, 2 new Important, 0 Minor; probe-shadowed CAS/idempotency and deletion generation/lease-epoch ABA require fixes; reviewer RH_Privat session `01a054cf-0d9f-7031-97cc-4bce1130df8a`
Task 3: fix round 2/5 running — resume implementer session `01a054bc-60e7-70c3-9208-9f011649f05e`; fix base `7bdd92613b24e0f65c0a48018a7684f6766fa51b`
Task 3: fix round 2/5 — 2 Important addressed; commit `d2bbcab423c19cff5d257644623526d8a4f6ac83`; RED 5 failed/1 passed; regressions 6 passed; focus 131 passed/45 deselected; unfiltered Task-3 files 176 passed; Ruff, compileall and diff-check green
Task 3: scoped re-review round 2 running — fix range `7bdd92613b24e0f65c0a48018a7684f6766fa51b..d2bbcab423c19cff5d257644623526d8a4f6ac83`
Task 3: scoped re-review round 2 — prior 2 Important closed; 0 Critical, 1 new Important, 0 Minor; `record_probe()` can mutate without advancing authoritative document generation and bypass generation exhaustion; reviewer RH_Privat session `01a054dd-189f-7f73-bd91-7e58518f96fa`
Task 3: fix round 3/5 running — resume implementer session `01a054bc-60e7-70c3-9208-9f011649f05e`; fix base `d2bbcab423c19cff5d257644623526d8a4f6ac83`
Task 3: fix round 3/5 — 1 Important addressed; commit `214ac6c38d885257727c3115f4b4f98026c5ce28`; RED 3 failed/2 passed; regressions 5 passed; unfiltered Task-3 files 181 passed; Ruff, compileall and diff-check green
Task 3: scoped re-review round 3 running — fix range `d2bbcab423c19cff5d257644623526d8a4f6ac83..214ac6c38d885257727c3115f4b4f98026c5ce28`
Task 3: scoped re-review round 3 — prior Important closed; 0 Critical, 0 Important, 0 Minor; reviewer RH_Privat session `01a054e1-e7c1-79b0-b452-40a258f428d6`
Task 3: complete — commits `f6c55eebaca39665e777a77d9242a3845ffc8a7c..214ac6c38d885257727c3115f4b4f98026c5ce28`; 181 Task-3 tests passed; scoped re-review clean; 0 deferred Task-3 findings
Task 4: pending
Task 4: running — implementer fresh RH_Privat session `01a054e4-f8a3-7221-b9e2-8bd93ac049c8`, base `214ac6c38d885257727c3115f4b4f98026c5ce28`
Task 4: implementation `b2779082f8f50d043bc43deb10d929682f6de34f`; RED 2 collection errors; 23 focused + 68 Task-1–3 regression tests passed; Ruff, compileall and diff-check green
Task 4: independent review running — exact range `214ac6c38d885257727c3115f4b4f98026c5ce28..b2779082f8f50d043bc43deb10d929682f6de34f`
Task 4: reviewer fresh RH_Privat session `01a054ed-f289-7902-bb92-9e28fa92c54e`
Task 4: review — 1 Critical, 1 Important, 1 Minor; fixes required; synchronous timeout-free TLS/request shutdown deadlock, uncaught wide Content-Length, mocked transport coverage gap
Task 4: fix round 1/5 running — resume implementer RH_Privat session `01a054e4-f8a3-7221-b9e2-8bd93ac049c8`; fix base `b2779082f8f50d043bc43deb10d929682f6de34f`
Task 4: fix round 1/5 — 1 Critical + 1 Important + 1 Minor addressed; commit `3c1161ef6fc01e2ae1e428d9f561fc6d6e847a8f`; RED 3 failed/7 passed; 41 focused + 68 Task-1–3 regression tests passed; live mTLS/lifecycle coverage; Ruff, compileall and diff-check green
Task 4: scoped re-review round 1 running — fix range `b2779082f8f50d043bc43deb10d929682f6de34f..3c1161ef6fc01e2ae1e428d9f561fc6d6e847a8f`
Task 4: scoped re-review round 1 reviewer fresh RH_Privat session `01a054fa-df8a-71e3-b530-fc4c12b45c92`
Task 4: scoped re-review round 1 — original Important and Minor closed; original Critical partially closed; 1 new/remaining Critical, 0 Important, 0 Minor; header/body inactivity timeout does not enforce absolute phase deadline
Task 4: fix round 2/5 running — resume implementer RH_Privat session `01a054e4-f8a3-7221-b9e2-8bd93ac049c8`; fix base `3c1161ef6fc01e2ae1e428d9f561fc6d6e847a8f`
Task 4: fix round 2/5 — remaining Critical addressed; commit `ab648fe0668dffc2c544f2186acb188fd2331679`; RED 2 failed; trickle regressions 2 passed; 43 focused + 68 Task-1–3 regression tests passed; Ruff, compileall and diff-check green
Task 4: scoped re-review round 2 running — fix range `3c1161ef6fc01e2ae1e428d9f561fc6d6e847a8f..ab648fe0668dffc2c544f2186acb188fd2331679`
Task 4: scoped re-review round 2 reviewer fresh RH_Privat session `01a05502-435f-7123-aec8-6bd0c17dcde0`
Task 4: scoped re-review round 2 — remaining Critical closed; 0 Critical, 0 Important, 0 Minor; focused daemon 31 passed; trickle regressions 5 repeated runs; CodeRabbit 0 findings
Task 4: complete — commits `214ac6c38d885257727c3115f4b4f98026c5ce28..ab648fe0668dffc2c544f2186acb188fd2331679`; 43 Task-4 + 68 Task-1–3 regression tests passed; scoped re-review clean; 0 deferred Task-4 findings
Task 5: pending
Task 5: running — implementer fresh RH_Privat session `01a05506-c84b-7fb3-a1ef-90c8ef5d2d12`, base `ab648fe0668dffc2c544f2186acb188fd2331679`
Task 5: RH_Privat usage exhausted after 15 focused + 137 regression tests and two CodeRabbit fix rounds; temporary allowed fallback to fresh BW_Nufker session `01a05518-99f0-7522-b464-b9762501ae39` for final audit/gates/commit
Task 5: implementation `ec2ecae`; RED 3 collection errors; 17 focused + 207 regression tests passed; CodeRabbit recovery race fixed; Ruff, compileall, diff-check and secret scan green; independent review running
Task 5: independent reviewer fresh temporary BW_Nufker session `01a05523-997e-7050-b2ab-7e7d0200fc32`
Task 5: review — 3 Critical, 7 Important, 0 Minor; fixes required; double mutating effect, false failed state, redirect credential escape, incomplete lease fence, unreal Ollama adapter, validation-only CLI, incoherent/unbounded state, ambiguous HTTP, unused TOCTOU path gate
Task 5: fix round 1/5 running — resume temporary BW_Nufker implementer session `01a05518-99f0-7522-b464-b9762501ae39`; fix base `ec2ecae53f866638381e47bdfc81849cdb5f6a09`
Task 5: fix round 1/5 — commit `a7a2856`; 40 focused + 184 relevant regression tests passed; review found 0 Critical, 7 Important, 3 Minor
Task 5: fix round 2/5 running — original implementer resumed at `a7a2856`; scope surgically extended by `ollama_runtime.py` and `test_ollama_runtime.py` for sealed public running adoption
Task 5: fix round 2/5 — 7 Important + M1–M3 addressed; 120 focused + 185 relevant regression tests passed; three CodeRabbit rounds, 5 valid follow-up findings fixed, final round clean; Ruff, compileall, diff-check and secret scan green
Task 5: fix round 3/5 running — original implementer resumed at `4887340`; exact lifecycle intent/stop/reconcile and monotonic deadline work only, no Task 6 transition
Task 5: fix round 3/5 — 5 Important addressed; 126 focused + 186 relevant regression tests passed; 12 CodeRabbit uncommitted rounds, final round 0 findings; Ruff, compileall, diff-check and secret scan green
Task 5: fix round 4/5 — rereview-3 mutable-memfd cache Important addressed; real unsealed RED `(True, True)`, sealed/unsealed live-kernel GREEN; 127 focused + 195 direct runtime-consumer regressions passed; CodeRabbit uncommitted round 1 returned 0 findings; Ruff, compileall, diff-check and secret scan green; no Task 6 transition
Task 5: scoped re-review round 4 — executable-adoption Important closed; 0 Critical, 0 Important, 1 documentation Minor; portable ledger correction independently re-reviewed with 0 findings
Task 5: complete — commits `ab648fe0668dffc2c544f2186acb188fd2331679..479b904f1cb60f76194f37ffd319c5086291716a`; 127 focused + 195 direct consumer regressions passed; final scoped verdict 0 Critical, 0 Important, 0 Minor
Task 6: pending
Task 7: pending
Task 8: pending
Task 9: pending
Task 10: pending
Task 11: pending
