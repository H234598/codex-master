# The Hive Control Plane

The Hive control-plane source coordinates work from typed, locally verified
inputs. It must not make caller-supplied identity or previously observed status
authoritative.

## Checked-in contract layers

- **Principals and authority:** the Hive configuration and class catalog define
  the checked-in principal and delegation shape. Runtime assembly and authority
  logic are under [`src/the_hive/hive/`](../src/the_hive/hive/).
- **Admission:** [`ServerAdmissionRuntime`](../src/the_hive/admission_runtime.py)
  is a server-facing fail-closed adapter. It is a source contract, not evidence
  that a productive executor is attached.
- **Selection:** selection and resolver code use policy and current evidence to
  produce advisory offers or an effective decision. See [Resolver](resolver.md).
- **Assignment binding:**
  [`create_assignment_admission`](../src/the_hive/hive/admission.py) binds
  checked inputs to an admission object; it does not by itself start an agent,
  reserve capacity, or invoke a provider.
- **Events and coordination evidence:**
  [`HiveEventStore`](../src/the_hive/hive/events.py) is documented in source as
  retaining sanitized queue and completion metadata. It is not a store for
  credentials, prompts, or raw agent output.
- **Recovery:** fleet recovery is handled through the checked-in recovery and
  service paths; unresolved external work remains a blocker. See
  [Recovery](operations/recovery.md).

## Fail-closed boundary

Do not treat a preview, a disabled state, or a stale offer as productive
activation. A mutation needs current authority, repository, scope, capability,
and other required evidence at the point it is made. Public objects are
intended to omit account keys, exact scope paths, lease identifiers,
credentials, prompts, terminal output, and absolute local roots; see
[Hive security](security/hive-security.md).

The prior Wiki page described a particular absence of numeric concurrency caps.
That assertion was not independently re-established for the current source
tree, so it is deliberately not stated as a current contract.

## Evidence limit

Checked-in modules and their tests do not demonstrate an enabled control plane,
provider execution, cross-store compensation, or a production deployment.
Before an operational claim, obtain authorized current status from the intended
environment. This documentation supplies no command that changes it.

## Related documentation

- [Architecture](architecture.md)
- [Resolver](resolver.md)
- [Hive operations](operations/hive-operations.md)
- [Hive security](security/hive-security.md)
- [Hive/Selection migration](migration/hive-selection-migration.md)
