# The Hive installation

The Hive is packaged as `the-hive` (version `0.10.5` in the checked-in
project metadata) and requires Python 3.11 or newer. A repository checkout is
not by itself an installed, enabled, or healthy runtime.

## Supported repository evidence

The checked-in MCP connection describes a deployment-configured stable local
launcher. The repository does not publish a portable launcher path to copy into
another environment. Its presence in the repository does not prove that a
release is present or valid on a machine.

[`bin/the-hive-mcp`](../bin/the-hive-mcp) is an attested release wrapper. It
requires a release root, generation, and manifest digest before any command
arguments. Do not invoke it as a normal checkout command.

The source-backed installer interface is:

```sh
./scripts/the-hive-hive-hourly-probe-install --home <absolute-home>
```

## Fleet watchdog migration

The Fleet watchdog is not a Codex-Usage publisher.  Once a trusted owner has
authorized the local target home, its one-way namespace migration is performed
only through this The-Hive transaction:

```sh
./scripts/the-hive-fleet-watchdog cutover --home <absolute-home>
```

The transaction binds the installed attested runtime and stable MCP launcher,
the old and new unit files, their identities and the current user-manager
states before it writes anything.  It stages the successor, refreshes the
user-manager, quiesces the old Fleet supervisor, activates the successor and
observes its bounded watchdog command before retiring the old units and wants.
On any failure it restores and verifies the bound prior state; a rollback
failure is fail-closed.  `status --home <absolute-home>` is the corresponding
read-only, data-sparse inspection route.  Do not replace this route with
hand-composed `systemctl` calls or let Codex-Usage manage these Fleet units.

`<absolute-home>` must name an existing absolute home directory. The installer
requires a clean checkout, builds and validates a manifest-attested runtime
generation, materializes the stable launcher beneath that home, and writes the
`the-hive-hive-hourly-probe.service` and
`the-hive-hive-hourly-probe.timer` user-unit files. This is a persistent local
write and release-publication action, not a diagnostic command.

## Authorization boundary

Run the installer only through a trusted owner's current instructions and with
explicit authorization for the target home. Apart from the Fleet-watchdog
transaction above, this repository does not provide a verified procedure for
user or system installation, unit activation, reload, secret provisioning, or
a live smoke test. In particular, creating user-unit files is not evidence
that the units are enabled or running.

Do not substitute an arbitrary Python invocation, alter release pointers, or
construct wrapper arguments manually. An attested generation binds its
manifest digest to the release layout.

## After an authorized installation

Use the intended deployment interface for bounded, data-sparse status and
diagnostics. The repository does not publish a general direct-CLI recipe for
that interface. Record the reported generation and manifest digest without
including secrets or raw private-state output.

See [configuration](configuration.md) for source-controlled inputs,
[troubleshooting](operations/troubleshooting.md) for safe evidence gathering,
and [releases](releases.md) for the release boundary.
