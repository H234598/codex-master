# The Hive troubleshooting

Troubleshooting begins with bounded evidence. It does not authorize direct
inspection or modification of private state, credentials, leases, managed
homes, release generations, or user-unit files.

## Gather safe evidence

1. Confirm the intended deployment and the authorized entry point with its
   owner. A repository checkout and its `bin/the-hive-mcp` wrapper are not a
   generic diagnostic interface.
2. Request current, data-sparse runtime status and diagnostics through that
   intended interface. The staged runtime validation uses Hive `status` and
   `doctor` diagnostics, but this repository does not establish a portable
   direct command line for operators.
3. Record bounded classifications, timestamps, release generation, and
   manifest digest when the interface exposes them. Exclude secrets, prompts,
   raw terminal output, and private filesystem paths.
4. Compare the result with the attested release and source-controlled
   configuration. Do not repair a mismatch by editing the runtime image or
   state store.

## Interpret blocked evidence

The runtime evidence path is explicitly read-only and returns a fail-closed
projection when configuration, repository binding, principals, or state cannot
be established. Common source-level classifications include unavailable or
invalid configuration/state, a blocked pilot, and fail-closed authority. They
are safety outcomes, not prompts to guess a repair.

Selection and pilot logic likewise does not turn static configuration into
authorization. Missing, stale, malformed, or insufficient account, authority,
repository, scope, capability, or lease evidence remains blocking.

## Escalate instead of mutating

Escalate to the trusted deployment or release owner when the release is not
attested, the current interface is unavailable, diagnostics are blocked, a
secret may be involved, or the required recovery action is not explicitly
authorized. State what was observed, what was not observable, and the target
scope. Mark unverified claims as unknown.

Do not use this page for installation, unit activation, secret provisioning,
reloads, restarts, recovery writes, or provider calls. See
[installation](../installation.md), [configuration](../configuration.md), and
[releases](../releases.md) for their respective boundaries.
