# The Hive Operations Runbook

This page is an evidence-first operating guide. It does not authorize
installation, activation, reload, restart, private-state inspection, provider
calls, or documentation publication.

## Start with the intended interface

Use the deployment-specific, authorized entry point and inspect its current
read-only status and diagnostic interface before proposing a mutation. Do not
turn this repository checkout into an invocation recipe:

- [`bin/the-hive-mcp`](../../bin/the-hive-mcp) is an attested release wrapper
  that requires three release-binding arguments before any command arguments;
- the checked-in man page is not used here as a command reference because parts
  of it have not been independently revalidated against the current routing and
  wrapper behavior; and
- a healthy process or a green local test does not establish fresh plugin
  state, provider availability, agent visibility, or an enabled Hive.

## Safe operational sequence

1. Obtain authorized, current, data-sparse status and diagnostics through the
   intended environment interface.
2. Identify the smallest read scope and any exact persistent write paths before
   proposing work.
3. Confirm current authority, repository, scope, capability, admission, and
   lease requirements at the mutation boundary.
4. Preserve bounded, redacted reports as operational evidence; do not use raw
   terminal logs or private state as a shortcut.
5. Independently review the resulting change and its focused checks. A worker
   report is not completion evidence by itself.

## Mutation and release boundaries

Destructive pool or home actions require explicit target verification and
separate authorization. The home-broker materials are an offline-audit release
artifact boundary; consult the
[home-broker runbook](the-hive-home-broker.md) rather than activating units
from this page.

The normal repository documentation is versioned under [`docs/`](../README.md).
There is no GitHub-Wiki publication workflow in the active documentation. Do
not copy documentation into a separate Wiki as an operational step.

## Related documentation

- [Architecture](../architecture.md)
- [Control plane](../control-plane.md)
- [Resolver](../resolver.md)
- [Recovery](recovery.md)
- [Agent pool](../agent-pool.md)
- [Hive operations](hive-operations.md)
