# DP0: real V2 Teamleiterin through Masterjet

**Goal:** Start a newly materialized, pool-only, persistent `teamleiterin` with
`gpt-5.6-terra` / `xhigh` from one established Codex-Usage profile source.

**Hard boundaries:**

- Legacy A/Q/B series homes are never selected, altered, repaired, or used.
- No V1-to-V2 compatibility path and no second registry/resolver.
- No auth content is logged or returned. Auth is projected only after an
  identity-bound canonical-profile check.
- A real CHPB/2 broker attestation is mandatory before any home publication or
  inventory CAS. No user-owned direct-write fallback.
- `cache_invalidated` remains a Codex-Usage concern; this slice only writes its
  technical handoff.

## Work slices

1. Add a focused contract for selecting one eligible OpenAI account from the
   existing V2 registry and validating its canonical Codex-Usage profile
   binding. Test invalid binding, series-only account, wrong provider, and
   exhausted/disabled candidates first.
2. Add a DP0 runtime-provisioning orchestrator which prepares generic and
   class policy projection, requires a committed CHPB/2 attestation, and
   returns a dynamic runtime descriptor. Test a successful fake broker and all
   fail-closed broker outcomes. The orchestrator must not write a home.
3. Wire only `teamleiterin` starts to the orchestrator before legacy home
   materialization. It must expose a stable broker gate while broker service or
   platform attestation is unavailable. Test exact call order and assert that
   legacy materialization is never called.
4. Add a Codex-Usage owner handoff defining the narrow, identity- and
   provenance-bound Last-Good use for transient app-server transport failures.
5. Review changed paths, run only targeted tests, commit. Install/reload and
   live-start only if a real verified CHPB/2 service is present; otherwise
   report exact terminal gate with no home or registry mutation.

## Verification

```bash
pytest -q tests/test_teamlead_runtime.py
pytest -q tests/test_server.py -k 'teamlead_v2 or teamleiterin'
python -m compileall -q src/codex_master
git diff --check
```

No full suite. No live auth inspection.
