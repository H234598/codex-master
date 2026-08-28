# Offline CHPB/2 and Registry V2 Cutover Slices

## Binding decision

The unreleased V2 registry remains `schema_version: 2`.  It is corrected
breakingly to use `runtime_principals`; there is no schema 3 and no reader for
the former V2 shape.  The V2 runtime model has no fleet-series identity.

## Global constraints

- Implement only offline contracts.  No broker process, socket, filesystem,
  store, home, auth projection/copy, install, reload, root, systemd, SELinux,
  or live cutover.
- Do not modify V1 other than already committed fail-early server behavior.
- Reuse no legacy series fields for V2 runtime principals.
- Every new or changed production behavior is test-first and has focused test
  evidence.  Run only focused tests plus Ruff, compile, and diff checks.
- Existing untracked identity/Linux primitives are review-only, not inputs to
  this implementation and not part of either commit.

## Task 1 — CHPB/2 offline request contract

Only modify `src/codex_master/fleet_home_broker_protocol.py` and
`tests/test_fleet_home_broker_protocol.py`.

Add canonical, bounded CHPB/2 request variants for `provision`, `replace`, and
`deprovision`.  Requests must be transaction- and binding-bound.  Extend pure
recovery state/rules as necessary so deprovision has a deterministic,
fail-closed terminal recovery path.  No filesystem, socket, or emulator side
effect is permitted.  Preserve strict canonical decoding and bounded input.

## Task 2 — Registry V2 runtime principals

Only modify `src/codex_master/fleet_registry.py`,
`tests/test_fleet_registry.py`, `schemas/codex-fleet-registry.schema.json`, and
focused registry schema fixtures if necessary.

Correct V2 in place: require `runtime_principals`, validate and serialize it,
and expose pure generation/CAS planners.  A runtime principal binds an enabled
OpenAI ChatGPT profile account to a non-secret HMAC
`credential_binding_id`; it must never contain or derive a series identity,
home path, or auth content.  V2 account binding uniqueness covers every
enabled account with a binding, not Gemini only.  Keep V1 parsing intact but
provide no compatibility reader for the former V2 shape.

## Handoff gate

After both tasks: separate diff review per worker, focused tests, Ruff,
compile, and diff check.  Commit each accepted slice on this branch.  Stop
before Slice 3; do not install, reload, or attempt a live start.

## Completed slice boundaries

- Slice A was accepted as `b214612` after an independent clean contract review.
  It adds only pure CHPB/2 data and recovery decisions; it creates no socket,
  filesystem object, store entry, home, emulator action, or runtime process.
- Slice B corrects unpublished schema version 2 in place.  A V2 document now
  requires `runtime_principals`; there is deliberately no parser for the
  former V2 shape and no schema version 3.
- A runtime principal remains bound to its registered OpenAI ChatGPT account
  and opaque profile HMAC even when disabled.  Only account *availability*
  (enabled/configured/ready) is conditional on the principal being enabled.
  This preserves identity provenance while allowing a dormant principal during
  a normal account outage.

## Deliberately deferred, separate work

- This slice does not activate a broker, transport, state store, home build,
  attestation, auth projection, install, reload, or live cutover.
- Existing direct `FleetSnapshotV2(...)` constructors outside the registry
  still use the former four-field construction.  They must be changed in the
  dedicated consumer/home cutover slice, together with their targeted tests;
  no compatibility default or old V2 reader is introduced here.
- JSON Schema's pre-existing V2 static-series prefix/provider constraint is
  narrower in Python than in schema.  It is unrelated to runtime principals
  and intentionally left for its owning static-series contract slice.
