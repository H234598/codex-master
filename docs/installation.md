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

The historical `the-hive-hive-hourly-probe-install` executable is an internal
installer entrypoint, not an operator interface. It intentionally rejects an
operator invocation with `runtime_lifecycle_cutover_required`.

## Fleet watchdog migration

The Fleet watchdog is not a Codex-Usage publisher. Once a trusted owner has
authorized the local target home, its one-way namespace migration is performed
only through this The-Hive transaction:

```sh
./scripts/the-hive-fleet-watchdog cutover --home <absolute-home>
```

The transaction binds the installed attested runtime and stable MCP launcher,
the old and new unit files, their identities and the current user-manager
states before it writes anything. It stages the successor, refreshes the
user-manager, quiesces the old Fleet supervisor, activates the successor and
observes its bounded watchdog command before retiring the old units and wants.
On any failure it restores and verifies the bound prior state; a rollback
failure is fail-closed. `status --home <absolute-home>` is the corresponding
read-only, data-sparse inspection route. Do not replace this route with
hand-composed `systemctl` calls or let Codex-Usage manage these Fleet units.

## Runtime lifecycle

Runtime lifecycle uses a public plan followed by explicit, journaled phases.
The plan is read-only and returns the contract digest that every later phase
must consume:

```sh
./scripts/the-hive-runtime-service plan --home <absolute-home>
```

Use the returned `plan_sha256` only when the result is
`runtime_lifecycle_plan_ready`. A blocked plan is not an approval. The current
checkout has no verified runtime-compatibility profile, so the real product
plan reports `runtime_release_compatibility_profile_missing` and blocks
installation. Do not edit the plan result, bypass that reason, or continue with
a blocked digest.

When a plan is ready, pass its digest unchanged through each phase, in order:

```sh
./scripts/the-hive-runtime-service cutover --home <absolute-home> \
  --plan-sha256 <plan-sha256> --phase install
./scripts/the-hive-runtime-service cutover --home <absolute-home> \
  --plan-sha256 <plan-sha256> --phase activate
./scripts/the-hive-runtime-service cutover --home <absolute-home> \
  --plan-sha256 <plan-sha256> --phase observe
./scripts/the-hive-runtime-service cutover --home <absolute-home> \
  --plan-sha256 <plan-sha256> --phase commit
```

The activation phase also requires a fresh Root Hook ABI receipt for the
installed generation. The receipt is written only after the Root owner verifies
the actual Root target, and `activate` rechecks both the receipt and installed
Root files under the Lifecycle lock before changing manager state. New runtime
images include the standalone standard-library owner as the attested member
`bin/the-hive-hook-abi-v1-install`. Its inputs are the same generation's
manifested `root-install-plan.json`, plugin descriptor, launcher, companion,
core module and hook files. The builder validates the member through
`RuntimeLayout.read_attested_file` before publishing the image.

The current installed generation has not been shown to contain this member,
and no Root operation has been performed. Before using the handoff below, an
operator must obtain an independently reviewed release record that binds the
source commit, the consumer-script digest, the user UID, the generation and the
manifest digest. The operator must not derive the approved script digest or
generation from the mutable current pointer. Once those independent values
exist and the generation is installed for that UID, the Root operator copies
the fixed generation member into a new private Root staging directory, checks
its owner, mode, link count and digest, and runs only that copy with isolated
Python. The consumer itself resolves the home from the UID and rechecks the
current pointer, manifest and required data before publishing its fixed Root
target. The user-owned `the-hive-mcp install-resource-scope-gate` command stays
fail-closed; it is not this Hook ABI owner and cannot claim its result.

The following command sequence is available only after the independent release
record supplies all `APPROVED_*` values. It must be run from a Root shell; it
does not execute code from a checkout or import Hive modules from the user's
home:

```sh
set -eu
: "${APPROVED_UID:?must come from the independent release record}"
: "${APPROVED_GENERATION:?must come from the independent release record}"
: "${APPROVED_MANIFEST_DIGEST:?must come from the independent release record}"
: "${APPROVED_HOOK_INSTALLER_SHA256:?must come from the independent release record}"
: "${APPROVED_ROOT_STATE_SHA256:?reviewed root-state snapshot required}"
USER_HOME=$(/usr/bin/getent passwd "$APPROVED_UID" | /usr/bin/cut -d: -f6)
test -n "$USER_HOME"
SOURCE="$USER_HOME/.local/lib/the-hive-runtime/generations/$APPROVED_GENERATION/bin/the-hive-hook-abi-v1-install"
STAGE_DIR=$(/usr/bin/mktemp -d -p /run the-hive-hook-abi.XXXXXXXXXX)
test "$(/usr/bin/stat -c '%u:%a' "$STAGE_DIR")" = '0:700'
/usr/bin/install -o root -g root -m 0755 "$SOURCE" "$STAGE_DIR/the-hive-hook-abi-v1-install"
test "$(/usr/bin/stat -c '%u:%a:%h' \
  "$STAGE_DIR/the-hive-hook-abi-v1-install")" = '0:755:1'
actual=$(/usr/bin/sha256sum \
  "$STAGE_DIR/the-hive-hook-abi-v1-install" | /usr/bin/cut -d ' ' -f 1)
test "$actual" = "$APPROVED_HOOK_INSTALLER_SHA256"
/usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C /usr/bin/python3 -I -B \
  "$STAGE_DIR/the-hive-hook-abi-v1-install" --inspect-root-state
# Compare root_state_sha256 from that complete read-only result with the
# independently reviewed APPROVED_ROOT_STATE_SHA256 before continuing.
/usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C /usr/bin/python3 -I -B \
  "$STAGE_DIR/the-hive-hook-abi-v1-install" \
  --uid "$APPROVED_UID" \
  --generation "$APPROVED_GENERATION" \
  --manifest-sha256 "$APPROVED_MANIFEST_DIGEST" \
  --expected-root-state-sha256 "$APPROVED_ROOT_STATE_SHA256"
```

The read-only snapshot is taken immediately before the Root mutation and its
digest must match the independently reviewed expected root-state digest. If
the target, receipt, owner lock, parent or committed upgrade marker changed
since that snapshot, the installer stops before publishing. A pending upgrade
marker records the exact target and receipt identities before the atomic
publish; rerunning the same approved generation and snapshot resumes only that
bound transaction. A committed marker retains the prior target under its
recorded backup name, and Lifecycle rechecks that backup's physical identity
before accepting the Root receipt.

An empty or unapproved value is a stop condition. The command sequence has not
been run with Root privileges, and this checkout has not produced the required
independent release record. Until both the packaged member and its independent
pins are available, the Root receipt prerequisite remains open and `activate`
must remain held. Do not replace the fixed generation path or Root target with
a caller-selected path.

After `activate` succeeds, publish the local plugin descriptor for that same
installed generation and manifest digest, then run `observe` and `commit` in
order. The plugin receipt is not required by `observe`, so publication cannot
retroactively authorize activation. `commit` rechecks both owner receipts and
their physical effects against the installed generation. Each receipt is valid
for one hour from its verified readback. If a receipt has expired, the affected
phase holds without declaring a product defect or restarting installation. The
corresponding owner must read back its existing effect and refresh its receipt.

`install` rebinds the current source, predecessor image, target files and
user-manager state before it records intent and invokes the attested installer.
`activate` records each manager operation before applying it. `observe` checks
the installed image, all bound files and all six manager states, then runs the
argumentless probe and records readback evidence. `commit` rechecks those
readbacks and closes the journal. Each phase revalidates the plan; if its
digest or any bound input changes, the phase stops without treating the old
plan as authority. The target home must be an existing absolute path.

After an interrupted phase, inspect its bounded result. Resume recovery only
with the same plan digest and an existing transaction journal:

```sh
./scripts/the-hive-runtime-service cutover --home <absolute-home> \
  --plan-sha256 <plan-sha256> --phase recover
```

Recovery removes or restores only effects whose journaled identities still
match. A `runtime_lifecycle_recovery_hold` result means the evidence is
incomplete or changed; preserve the journal and affected paths for review.
Do not remove stages, pointers, units or lock files by hand. The historical
one-shot `cutover --home <absolute-home>` interface and the internal
`the-hive-hive-hourly-probe-install` entrypoint are fail-closed and are not
operator shortcuts.

`status --home <absolute-home>` and `verify --home <absolute-home>` are
read-only and return bounded JSON. They do not start, enable or repair units.
Do not compose `systemctl`, wrapper, pointer or unit-file steps outside the
phased transaction.

Do not substitute an arbitrary Python invocation, alter release pointers, or
construct wrapper arguments manually. An attested generation binds its
manifest digest to the release layout.

## After an authorized installation

Use `./scripts/the-hive-runtime-service verify --home <absolute-home>` for the
bounded, data-sparse postcondition report. Record its generation and manifest
digest without including secrets or raw private-state output.

See [configuration](configuration.md) for source-controlled inputs,
[troubleshooting](operations/troubleshooting.md) for safe evidence gathering,
and [releases](releases.md) for the release boundary.

## Bound local Hive plugin descriptor

After the root Hook ABI and its allowlist have been independently verified for
the active Runtime Image, the owner can publish that image's canonical hook
descriptor into the configured local `the-hive@personal` source:

```sh
./scripts/the-hive-plugin-release-publish \
  --home <absolute-home> --generation <active-generation> \
  --manifest-sha256 sha256:<active-manifest-digest> \
  --descriptor-sha256 sha256:<verified-descriptor-digest>
```

This source-only operator attests the current release pointer and image,
checks the local marketplace mapping, registration files, hooks and Fleet skill
against the attested bundle, and publishes only an absent descriptor. An
already matching descriptor is a no-op; any different target or input holds.
It does not install a Runtime Image, write the root ABI, edit hook trust or
settings, or update a Codex plugin cache.

Codex 0.161 refreshes an installed local plugin of the same version with
`codex --no-daemon plugin add the-hive@personal`. Run that native command once
for each separately bound `CODEX_HOME` that actually consumes the plugin,
then independently compare its cached `release-binding.json` with the active
Runtime descriptor. `plugin marketplace upgrade` applies to Git marketplace
snapshots and does not refresh this local source. Keep personal config and
trust values under their own backup and compare-and-swap gate.
