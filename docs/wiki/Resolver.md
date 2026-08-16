# Resolver

> Canonical repository source: `docs/wiki/Resolver.md`  
> Last verified: 2026-08-14 against the local source tree  
> Publication status: local source; not yet published to GitHub Wiki

The central resolver is shared by start and assignment paths. This page is an
orientation layer; it deliberately does not duplicate the normative class,
model, lifecycle, or effort matrices.

## Selection flow

1. Request the current valid combinations for the concrete target series.
2. Choose one offered class/lifecycle/model/reasoning tuple when possible.
3. Supply explicit values only when needed; omitted values come from class,
   lifecycle, task, and account-aware defaults.
4. Start or assignment resolves through the same implementation and rechecks
   current availability before mutation.
5. When fallback occurs, inspect requested/effective values and reason codes;
   accept the effective tuple, choose another offered tuple, or stop.

Hard class, lifecycle, authority, capability, and effort bounds win over stale
or incompatible requests. Availability fallback must remain visible; callers
must not silently force a rejected tuple.

## Canonical policy sources

- [Class catalog](../../codex-agent-classes.json)
- [Model policy](../../codex-model-policy.json)
- [Class schema](../../schemas/codex-agent-classes.schema.json)
- [Model-policy schema](../../schemas/codex-model-policy.schema.json)
- [Account-aware selection](../account-aware-selection.md)
- [Selection operations and fallback contract](../operations/selection-operations.md)
- [Selection privacy](../security/selection-privacy.md)

## Evidence boundary

Checked-in catalogs and tests prove local resolver behavior only. Productive
offers still depend on current account, capability, authority, admission, and
usage evidence. Query them at invocation time.
