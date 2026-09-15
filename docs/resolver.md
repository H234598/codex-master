# The Hive Resolver

The resolver is the orientation layer for class, lifecycle, model, reasoning,
capability, authority, and account-aware selection. It does not duplicate the
normative JSON catalogs.

## Current source-backed inputs

- [`codex-agent-classes.json`](../codex-agent-classes.json) is the checked-in
  class catalog, with
  [`codex-agent-classes.schema.json`](../schemas/codex-agent-classes.schema.json).
- [`codex-model-policy.json`](../codex-model-policy.json) is the checked-in
  model policy, with
  [`codex-model-policy.schema.json`](../schemas/codex-model-policy.schema.json).
- The server implements an `agent_selection_options` MCP tool for a single
  target and supports a prior `known_generation` value. The offer is advisory:
  it reports whether the generation changed and does not reserve a slot.
- Resolver tests cover visible fallback reason codes, including
  `requested_model_unavailable`. Fallback is therefore information for the
  caller to examine, not silent acceptance of a rejected request.

The source tree contains both selection modules and server integration. The
specific current offer is still contingent on authority and other current
evidence, so checked-in catalogs must not be used to reconstruct a live model
matrix.

## Selection boundary

Use the current offer for the concrete target when an authorized interface is
available. Class, lifecycle, authority, capability, availability, model, and
reasoning bounds take precedence over stale or incompatible input. A later
mutation must validate again; an offer neither reserves an agent nor proves
provider availability.

Account and usage data are private selection inputs. Public output is limited
to bounded identifiers and reason information; it must not expose account keys,
provider credentials, prompts, raw output, or absolute private paths. See
[Account-aware selection](account-aware-selection.md) and
[selection privacy](security/selection-privacy.md).

## Historical Wiki selection-flow record

The following five steps preserve the complete selection-flow section of the
former `docs/wiki/Resolver.md` at repository snapshot
`b5def7d6156d7862606a0edcbd7226652cf4833f`. This is a **historical workflow
state of the Wiki source, not verified as current operating instructions**.
It does not supply a current invocation, prove availability, or authorize a
start or assignment.

1. Request the current valid combinations for the concrete target series.
2. Choose one offered class/lifecycle/model/reasoning tuple when possible.
3. Supply explicit values only when needed; omitted values come from class,
   lifecycle, task, and account-aware defaults.
4. Start or assignment resolves through the same implementation and rechecks
   current availability before mutation.
5. When fallback occurs, inspect requested/effective values and reason codes;
   accept the effective tuple, choose another offered tuple, or stop.

The former flow's hard-bound statement is retained with the same historical
status: class, lifecycle, authority, capability, and effort bounds win over
stale or incompatible requests, and an availability fallback must remain
visible rather than silently forcing a rejected tuple. Current source-backed
limits are stated in the surrounding sections; this record does not create a
second live model matrix.

## Evidence limit

The catalogs, source, and tests cover local behavior. They do not prove that a
provider, account, capability, grant, admission condition, or usage datum is
currently available. Unknown or stale evidence remains a blocker.

## Related documentation

- [Architecture](architecture.md)
- [Control plane](control-plane.md)
- [Selection operations](operations/selection-operations.md)
- [Hive security](security/hive-security.md)
