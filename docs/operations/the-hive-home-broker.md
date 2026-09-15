# The Hive Home Broker Offline Operations Runbook

## Scope and hard boundary

This is an offline-audit checklist for the home-broker package, its unit
sources, and its SELinux source and file contexts. It records evidence and
release boundaries only; it does not install, activate, connect, or invoke
anything.

No installation, policy load, unit activation, or runtime invocation occurs in this runbook.
No connection is established in this runbook.

The socket unit is a tracked release artifact only. This runbook neither
activates it nor establishes a broker/agent connection.

The root-owned manifest/verifier is a release-artifact boundary; the verifier checks declared entries for uid/gid zero.

`StateDirectory=codex-master-home-broker` and the corresponding paths below
are historical technical compatibility contracts. They are not a product name;
the artifact and all unit names in this runbook are The Hive.

No static UID, GID, SELinux user, MCS category, or policy fallback is permitted.

## Artifact inventory

The closed inventory for this audit is:

- `src/the_hive/fleet_home_broker_package.py` — package manifest,
  canonical bytes, SHA-256, and Python import closure verification.
- `systemd/system/the-hive-home-broker.service` — root-owned broker
  verifier unit source.
- `systemd/system/the-hive-home-broker.socket` — bound broker socket unit
  source.
- `systemd/system/the-hive-agent@.service` — dynamic-user agent launcher
  unit source.
- `systemd/selinux/the_hive_home_broker.te` — broker and agent policy
  source for static review.
- `systemd/selinux/the_hive_home_broker.fc` — static file-context source.

Evidence is limited to these named artifacts and the release artifact boundary
described below.

## Offline evidence checklist

Record the following without executing an installer, verifier, unit, policy,
socket, SCM path, or network path:

- Packageclosure: exact closure. Declared entries must equal the package
  inventory exactly; missing and extra entries fail the gate.
- Preserve and review the canonical bytes for the manifest. Record the raw
  SHA-256 of every declared file and of the canonical manifest bytes.
- For every declared entry, record exact mode, uid=0, gid=0, regular file,
  and link count=1. Any metadata drift fails the gate.
- Check the Python import closure against the package entries. Every imported
  Python file must be declared and its digest must match the package entry.
- Keep the root-owned manifest/verifier boundary explicit. The verifier
  checks declared entries for uid/gid zero; it does not grant ownership or
  repair metadata.
- Confirm: Broker-write nur StateDirectory; Agent ohne State/RuntimeDirectory.
  `StateDirectory` is the only broker write boundary, and the agent receives
  no State/RuntimeDirectory allocation.
- Keep raw SHA-256 values and the canonical manifest blob available for the
  release handoff. Do not replace raw evidence with a summary.

This is an Offline-Auditcheckliste. A checklist item is evidence to review,
not an instruction to run a live command.

## Systemd unit audit

Review both unit sources as static text. Keep broker and agent contracts
separate:

- Broker unit must declare `StateDirectory=codex-master-home-broker`,
  `StateDirectoryMode=0700`, and `ProtectSystem=strict`. Its write boundary
  is only that StateDirectory.
- Agent unit must declare `DynamicUser=yes`, `PrivateUsers=yes`, and
  `PrivateMounts=yes`. The agent has no `StateDirectory` or
  `RuntimeDirectory`.
- Check `ProtectSystem=strict` for both units, and record the absence of
  `ReadWritePaths` and `[Install]` (`kein ReadWritePaths/[Install]`). No
  activation edge is part of this runbook.
- Check `RestrictAddressFamilies=AF_UNIX` and
  `SystemCallFilter=~@mount @module @keyring bpf` in both unit sources.
- Check that the socket unit binds only
  `/run/the-hive-home-broker.sock`, has `SocketMode=0600`, targets the broker
  service, and has no `[Install]` activation edge. The audit does not activate
  the socket or infer a broker/agent connection.

The unit audit is source review only. It does not establish Fedora runtime
semantics, filesystem ownership, activation state, or live permissions.

## SELinux static audit

Perform only a statische Source/Filecontexts-Audit of
`the_hive_home_broker.te` and `the_hive_home_broker.fc`:

- Confirm minimale Broker-/Agent-Typen: only the broker domain, executable,
  package/config/state types and the agent domain, executable/home/endpoint
  types needed by the named source are present.
- Confirm transitions and allow rules are limited to those minimal types and
  declared source relationships. No unrelated domain, user, fallback, or
  network permission may be added.
- Confirm every file-context security level is `s0 ohne Kategorie`. No MCS
  category, SELinux user, static UID, or static GID is encoded in the source.
- Treat the broker and agent as explicitly unconnected. The sole broker socket
  file-context is `/run/the-hive-home-broker.sock` with the declared runtime
  type; no SCM or network path may be inferred from it (`kein Socket/SCM/Netzpfad`).

This SELinux review is static source and file-context review only. It does
not load policy, relabel files, change enforcement, or validate a running
system.

## Release gate and handoff

Release handoff is allowed only when the offline evidence checklist, unit
source audit, and SELinux static audit are complete and their raw evidence is
preserved. Handoff includes the exact package closure, canonical manifest
bytes, raw SHA-256 values, modes, root ownership metadata, regular-file and
single-link evidence, and the Python import closure result.

The root-owned manifest/verifier remains a release artifact boundary. The
verifier checks declared entries uid/gid zero; it is not an installation,
activation, policy-loading, or runtime step.

Fedora Enforcing semantic validation is a separately authorized release gate.
Real Fedora-Enforcing behavior, real filesystem rights, and real activation
are separate gates and are not established by this offline runbook.

No static UID, GID, SELinux user, MCS category, or policy fallback is permitted.
