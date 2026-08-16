# Control Plane

> Canonical repository source: `docs/wiki/Control-Plane.md`  
> Last verified: 2026-08-14 against the local source tree  
> Publication status: local source; not yet published to GitHub Wiki

The Hive control plane coordinates work without making caller-supplied identity
or stale status authoritative.

## Contract layers

- **Principals and authority:** identify who may delegate each class and scope.
- **Admission:** checks global capacity, task capability, resource policy, and
  structured denial reasons before work is accepted.
- **Selection:** applies the central resolver to currently valid offers.
- **Assignment binding:** records the approved principal, scope, write paths,
  lifecycle, and effective selection at the execution boundary.
- **Queue, messages, memory, and decisions:** preserve coordination evidence
  without exposing secrets or raw Agentin output.
- **Recovery and saga contracts:** reconcile interrupted local transitions and
  retain unresolved external work as explicit state.

## Fail-closed rules

- Missing identity, scope, metrics, account evidence, or required grants does
  not become an implicit allow.
- Preview or disabled state is not productive activation.
- A selection offer is advisory and reserves neither an Agentin nor a slot.
- Mutations require a fresh lease and admission check.
- Public responses remain bounded and redacted.

## Operational evidence boundary

The repository contains local implementations and tests for these contracts.
Operators must still inspect live `hive-status`, admission, selection, and Queen
state before claiming an operational control plane. Local tests do not prove a
provider executor, cross-store compensation, multi-Queen pilot, or enforced
production mode.

## Canonical detail

- [Hive operations](../operations/hive-operations.md)
- [Hive security and authority](../security/hive-security.md)
- [Selection migration](../migration/hive-selection-migration.md)
- [Selection operations](../operations/selection-operations.md)
- [Project CLI overview](../../README.md#local-cli)
