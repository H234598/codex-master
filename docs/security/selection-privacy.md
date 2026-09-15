# The Hive Selection Privacy

Account and usage data are internal selection inputs. Account keys are opaque
local identities and are never returned by preview, admission, status, or Hive
diagnostics. Provider credential values are not read by the selection planner.

Selection output is intended to be limited to bounded agent/model identifiers,
band, eligibility reasons, aggregate counts, freshness categories, and
`raw_output: not_returned`. Payloads containing private account fields are
rejected by the typed normalizers. Individual reporting paths have separate
contracts and must not be assumed to provide this same redaction boundary.

Do not place `auth.json`, API tokens, prompts, terminal output, provider
headers, or absolute state paths in a fixture or audit record. Local API tokens
are managed outside the repository. This document does not prescribe a local
credential path; historical state and environment names remain technical
compatibility identifiers, not product branding.

Stale or unknown usage semantics fail closed. The passive SP0 planner can
describe a due anchor but cannot execute it until the separate sandbox,
token-budget, runtime, and kill-switch safety contract is verified.
