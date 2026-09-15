# The Hive development and focused checks

The checked-in package metadata names the project `the-hive`, version
`0.10.5`, and requires Python 3.11 or newer. It exposes the console-entry
names `the-hive-mcp`, `the-hive-admin`, `the-hive-agent-api`,
`the-hive-host-agent`, and `google-account-manager`. Declaring an entry point
does not make a checkout a trusted runtime installation.

## Public documentation OPSEC

Treat published documentation as public and machine-indexable by default. It
must not include:

- personal identifiers, including real names, user names, email addresses, or
  private account names;
- secrets and credentials, including keys, tokens, cookies, credential
  identifiers or material, or values from credential files;
- internal resource identifiers, including session, lease, invocation,
  subject, project, or billing identifiers that are not explicitly public
  examples;
- private network addresses and local absolute paths; or
- raw logs, stack traces, or screenshots that expose identities, paths,
  window titles, metadata, or credentials.

Use portable placeholders such as `$HOME`, `<account>`, `<host>`, `<repo>`,
and `<session-id>` instead. Keep internal operational documentation clearly
separate from public project documentation. Secrets are never permitted, even
there. If an operational identifier is truly necessary, put it only in an
explicitly access-restricted internal document.

## Focused verification

The CI workflow establishes the test invocation shape
`PYTHONPATH=src python -m pytest -q`. For changes touching the associated
contracts, the following focused command is source-backed:

```sh
PYTHONPATH=src python -m pytest -q \
  tests/test_diagnostics.py \
  tests/test_hive_bus_types.py \
  tests/test_hive_runtime.py
```

These tests cover data-sparse diagnostics, Hive bus values, and Hive runtime
evidence. They are not a substitute for deployment evidence, provider
availability, credentials, or a running fleet. Choose narrower or additional
tests when a changed source module has a more specific test file.

The repository declares optional `google-identity` and `test-index`
dependencies. No complete local environment-bootstrap procedure is verified in
the project metadata, so obtain approved development-environment instructions
instead of treating this page as an installation recipe.

## CI status boundary

The checked-in workflow is useful as a source for checks, not as proof of a
green run. Its manifest-validation step still expects the historical
`codex-master` keys, whereas the checked-in plugin and app manifests use
`the-hive`. This known conflict prevents a source-backed green-CI claim; the
last remote CI result is unknown here.

Do not use a documentation-only check to infer release readiness. See
[releases](releases.md) for the attested-image boundary and
[troubleshooting](operations/troubleshooting.md) for failure evidence.
