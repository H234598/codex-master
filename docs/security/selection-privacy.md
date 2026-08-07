# Selection Privacy

Account and usage data are internal selection inputs. Account keys are opaque
local identities and are never returned by preview, admission, status, or Hive
diagnostics. Provider credential values are not read by the selection planner.

Selection output is limited to bounded agent/model identifiers, band,
eligibility reasons, aggregate counts, freshness categories, and
`raw_output: not_returned`. Payloads containing private account fields are
rejected by the typed normalizers.

Do not place `auth.json`, API tokens, prompts, terminal output, provider
headers, or absolute state paths in a fixture or audit record. Local API tokens
are managed outside the repository in
`/home/teladi/.config/codex-master-mcp/api-token.env` with private permissions.

Stale or unknown usage semantics fail closed. The passive SP0 planner can
describe a due anchor but cannot execute it until the separate sandbox,
token-budget, runtime, and kill-switch safety contract is verified.
