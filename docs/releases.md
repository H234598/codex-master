# The Hive releases

This repository documents an attested local runtime-image mechanism, not a
complete release-authorization process. Who may approve a release, which
environment receives it, and the required sign-off are not established by the
checked-in sources and remain owner decisions.

## Source-backed release boundary

[`scripts/the-hive-hive-hourly-probe-install`](../scripts/the-hive-hive-hourly-probe-install)
is the checked-in publication path. It accepts `--home`, refuses a dirty
checkout, builds a runtime image, writes a manifest, validates the staged
image, and publishes one manifest-attested generation under an exclusive
release lock. A generation is bound to its manifest digest; the stable MCP
launcher is materialized from that attested generation.

The script also materializes the hourly-probe user-unit files for that
generation. It is therefore a state-changing publication action, not a
release-preview or diagnostic command. The repository does not verify a
general system-install, user-unit activation, reload, rollback, or remote
rollout procedure.

## Release evidence and escalation

For an owner-authorized release, retain the approved checkout identity and the
installer's bounded result fields (`generation` and `manifest_digest`) as
release evidence. Do not replace the manifest, pointers, launcher, or unit
files manually. If the staged validation or attestation fails, keep the result
blocked and escalate to the release owner with the bounded failure status.

An observed local runtime or test result does not prove a remote deployment,
provider transaction, or successful service activation. Those claims require
separate current evidence.

See [installation](installation.md) for the installation boundary,
[development](development.md) for focused contract checks, and
[troubleshooting](operations/troubleshooting.md) for safe failure reporting.
