# codex-master

The Hive (legacy names: `codex-master`, `codex-master-mcp`, and Masterjet) is
the local MCP control plane for a sleeping/scalable Codex Agentinnen fleet.
The Fleet Registry is authoritative for active series; the legacy pool spec is
kept only for compatibility.

Versioned local Wiki sources start at [docs/wiki/Home.md](docs/wiki/Home.md).
They remain canonical in this repository; no GitHub Wiki publication is implied.
Fleet-Overview, G-Serie and Goddess-Reporting contract: [docs/operations/goddess-reporting.md](docs/operations/goddess-reporting.md).

- `/home/teladi/.codex-agents/a1` through `/home/teladi/.codex-agents/a100`
- `/home/teladi/.codex-agents/b1` through `/home/teladi/.codex-agents/b100`
- `/home/teladi/.codex-agents/c1` through `/home/teladi/.codex-agents/c100`

Legacy selectors `a` and `b` map to `a1` and `b1`; `both` maps to `a1,b1`.
Series selectors `a-series`, `b-series`, `c-series`, and `all` are available
for status, skills, capabilities, lease status, start/stop, and watchdog calls.
Selectors are case-insensitive, so `A1`, `a1`, `A-Series`, and `a-series`
resolve identically. Numeric single-Agentin selectors use the current selector
policy. The default policy is alternating A/B: `1=a1`, `2=b1`, `3=a2`,
`4=b2`, and so on. Change it with:

```sh
./bin/codex-master-mcp selector-policy --series a,b,c
./bin/codex-master-mcp selector-preview --series a,b,c --limit 6
```

The policy is stored in private MCP state and can also be overridden for a
process with `CODEX_MASTER_AGENT_SELECTOR_SERIES=a,b,c`.
Teamleiterinnen may spawn fremde Bienen directly through the Masterjet with
`agent_start`, `agent_claim`, and the structured `agent_assign*` tools. Leases,
auth checks, and write scopes are the coordination boundary; they are not a
reason to avoid using available fremde Bienen.
The original authenticated homes are preserved as `a1` and `b1`. Additional
homes are intentionally slim and sleeping by default; they have their own
`CODEX_HOME`, wrapper, config, tmux session name, lease, and metadata, while
large read-mostly skill/plugin/model cache files may be symlinked from a series
template. C-series homes are intentionally unauthenticated until another
account is available.

The wrapper starts instances through their per-home `codex` launcher files.
Before central resolution supplies an effective tuple, its base default is
`gpt-5.6-luna` with medium reasoning:

```sh
--model gpt-5.6-luna -c 'model="gpt-5.6-luna"' -c 'model_reasoning_effort="medium"' --yolo -s danger-full-access --search
```

It uses `tmux` as the PTY backend. Full terminal output is written only to local
state files under `~/.local/state/codex-master-mcp/raw/`. New raw logs are
bounded to 5 MiB per file, and managed raw-log directories keep at most 20 files
by default. Prepared raw-log files are created with no-follow exclusive
semantics. The direct raw-log writer also requires the managed state directories
and their parent chains to be real directories, not symlinks, and legacy raw-log
directories are ignored when they are symlinks. Agentin runners must be regular executable files, not
symlinks. Assignment-log reads require regular files, are capped, and use
generic errors. Private state file and directory errors are generic and avoid
returning local state paths. Agentin metadata presence checks do not follow
symlinks, metadata reads reject symlinked and oversized files, and metadata read
errors use generic markers rather than local file paths. Safe-tail log reads
ignore non-regular raw-log targets. Tmux control errors are redacted and bounded
before they are returned or raised. MCP tool responses do not return raw output
by default and expose raw-log presence without returning local raw-log paths.
Text is pasted into the Codex TUI through tmux and submitted with plain `Enter`.
Multiline prompts use bracketed-paste markers so the complete prompt remains one
composer entry before submission.
Before pasting, `send`, `assign-*`, and `report-request` wait briefly for an
identifiable Codex TUI input prompt marker in the current visible pane tail. If
the Agentin is still in startup warnings, only shows starter text, or no input
prompt is visible, the mutation fails closed with retryable
`agent_input_not_ready`, `paste_attempted: false`, and
`raw_output: not_returned` instead of losing the prompt into the startup screen.
Existing metadata under the old `codex-agent-mcp` state directory is still read
as a migration fallback. External `tmux`, `git`, and `codex mcp` subprocesses
are timeout-bounded so MCP calls fail closed instead of hanging indefinitely.
MCP registration checks compare the exact `command:` field from
`codex mcp get`, not a broad substring in command output.
Agentin lifecycle operations that mutate or send into tmux sessions are
serialized per Agentin with private no-follow lock files, so different
Agentinnen can still run independently while concurrent starts/stops/sends for
the same Agentin cannot interleave. If `tmux new-session` fails before this
process created a session, cleanup removes only the prepared raw log and does
not kill an existing session that may belong to another MCP process.
Mutating tools also use a per-Agentin lease, so two Codex-CLI instances cannot
silently assign or send into the same Agentin at the same time. Lease conflicts
return structured retry metadata (`error_code`, `retryable`,
`retry_after_seconds`, and remaining lease seconds) without exposing client
identity. `agent_claim` retries forever by default when a fremde Biene is busy;
finite `wait_seconds` values remain available but are not capped at 600 seconds.
Use `--no-wait` for a single immediate claim attempt. The default poll interval
is 30 seconds and the maximum poll interval is 900 seconds.
Explicit claims also recover a foreign held lease when the Agentin is no longer
running, no process is using that Agentin home, and local idle evidence is at
least 120 seconds old. This stopped-orphan recovery can be disabled with
`--no-recover-stopped`; it does not apply to implicit send/report/interrupt
mutations and it never overrides a running foreign Agentin.
Short-lived CLI invocations derive a stable, hidden owner from `CODEX_THREAD_ID`
when Codex provides it, so the same Schwesterinstanz can claim, assign, request
reports, and release across separate CLI calls. `CODEX_MASTER_MCP_INSTANCE_ID`
remains an explicit override for controlled sessions. The derived identity is
never returned in public responses.
`agent_start` uses only a transient fresh lease and releases it after a
successful start, so short-lived local CLI commands do not block the next
operator command. Use `agent_claim` explicitly when a connected Codex-CLI
instance should keep an Agentin reserved after startup.
Mutating Start/Stop selectors that resolve to more than 6 Agentinnen fail
closed unless `allow_broad_selector=true` is passed. This prevents accidental
`all`/series operations from starting or stopping large parts of the pool.
Working mutations require a regular per-Agentin `auth.json` by default:
`agent_start`, `agent_claim`, `agent_send`, `agent_interrupt`, `agent_assign`,
`agent_assign_readonly`, `agent_assign_live_data`, `agent_assign_write`, and
`agent_report_request` fail closed when auth is missing, symlinked, not a
regular file, unreadable, or too large. Status/skills/capabilities/lease/pool/
stop/release remain available for diagnosis and cleanup. Use
`--allow-unauthenticated` only for explicit login/bootstrap flows.
For ChatGPT auth, status also checks a JWT access-token expiry when present.
An expired access token is reported as `access_token_expired` and blocks new
mutations until that Agentin is logged in again. Copying one rotating ChatGPT
refresh token into multiple Agentinnen is unsupported; each Agentin needs its
own login.
`agent_status` classifies bounded pane/log text without returning it, so callers
can distinguish likely daily, weekly, token, quota, or rate limits from ordinary
"no response yet" states. The classification keeps default Agentinnen-model
limits separate from Spark write-model limits and reports only metadata plus
`evidence: not_returned`. Limit metadata separates the running session model,
the latest assignment model, and the model inferred for the detected limit.
It also classifies a known Codex TUI starter/placeholder context without
returning pane text, so callers can tell when an Agentin did not receive the
assignment as productive input.
Public `status`, `skills`, `capabilities`, `app-bridge-status`,
`plugin-status`, `namespace-status`, `release-status`, `watchdog-status`,
`timeout-policy`, and `doctor` responses do not return local Agentin home,
runner, repo, manifest, or working directory paths; they return state/category
metadata such as `path_state`,
`home_kind`, and `cwd_state` instead.
Public scope checks, worktree status, command excerpts, and assignment audit
reads redact absolute local paths as well; assignment prompts still receive the
explicit paths that the Teamleiterin assigned.
`agent_wait` lets callers wait for activity, process exit, or a classified
limit without automatically receiving Agentin output. It defaults to 120 seconds
and is capped at 10 minutes per call. Its poll interval defaults to 30 seconds
and is capped at 900 seconds.
Assignments are asynchronous. `agent_wait` and `agent_report_request` expose
the relevant `assignment_id` at top level. Call `agent_assignment_report` with
that ID to receive a small ANSI-stripped, redacted terminal excerpt. This is
the explicit output boundary; assignment metadata and wait results remain
data-sparse.
`fleet_watchdog` checks idle Agentinnen without reading raw output. It defaults
to a 60 second idle threshold and asks the Agentin for a concise report before
any escalation. The report grace window defaults to 15 seconds, so the next
systemd timer pass can escalate only after the Agentin had one interval to
report. The installed systemd supervisor uses `--action stop`, so unused
Agentinnen are put back to sleep instead of being left active. By default the watchdog only mutates
Agentinnen leased by the current server; the systemd supervisor uses
`--manage-unclaimed --quiet` to handle unclaimed or expired leases while still
skipping active leases held by other clients and avoiding successful JSON noise
in the user journal.
Each fleet watchdog run creates one immutable in-memory fleet snapshot for the
managed process homes and tmux sessions. Agent evaluation reuses that snapshot;
standalone `agent_status` calls retain the legacy live-query fallback. Lease
release paths revalidate the live session/process identity immediately before
the release. An unavailable tmux observation is reported as unknown and skips
watchdog actions; it is never interpreted as a stopped session.
`usage-watchdog` consumes `codex-usage` snapshot state, writes a local
codex-usage block marker, and stops running Agentinnen whose accounts have a
future verified reset. A verified reset already in the past clears the block;
an unknown reset remains fail-closed. `agent_start`, claim, send, and
report-request flows refuse to use a blocked Agentin until the watchdog
releases it again.

## Fleet accounts, series, and Gemini headless jobs

The Fleet registry is the source of truth for every provider-backed series and
for native A/B/C materialization. The project is canonically named **The
Hive**; the legacy names above remain valid aliases. Use the read-only
account/series views first, then synchronize credentials locally through the
stdin-only CLI flow:

```sh
python3 -m codex_master.server fleet account list
python3 -m codex_master.server fleet series list
python3 -m codex_master.server fleet provider-models --provider ollama_local
python3 -m codex_master.server fleet account sync-env --first-key 1 --last-key 30
```

Secrets may be entered transiently in the control center or stdin flow, but
are never displayed, persisted in UI state, or returned by UI or normal MCP
output. They are stored only in private sidecars and are never part of the
registry, assignments, or shell history. Account gates require a configured
secret and a successful admission check. Stale or unknown Gemini probes are
checked once at invocation time, so a neighboring project does not make this
project stale. Gemini RPM/TPM/RPD observations are project-scoped; billing
tier and spend caps may still be shared by the billing account. The supplied
AI Studio exports confirm Tier 1 for `the-hive-1` and `the-hive-2`, and Tier 0
for `the-hive-3`, `the-hive-4`, `the-hive-6`, and `the-hive-10`. This is
project-scoped evidence; the local account group is not used to infer a
project's tier. Exact RPM/TPM/RPD limits remain model- and project-specific;
known values are imported only for projects with a Rate Limit table in the
supplied snapshots and unknown values are never guessed locally. Tier 1's
documented spend guard is $10 per rolling 10 minutes and its billing-account
cap is $250 per month. The local usage calculator reports observed RPM/TPM/RPD
and now uses the supplied AI Studio snapshots for known project/model pairs.
It keeps the limits model-specific and returns `model_required` or
`limits_unknown_dashboard_required` when no applicable snapshot exists. Spend
utilization remains `billing_export_required` because an API key alone does not
expose billing spend.

Imported rate-limit snapshots:

| Model | Tier 0 | Tier 1 |
| --- | --- | --- |
| Gemini 3.1 Flash Lite | 15 RPM / 250K TPM / 500 RPD | 4K RPM / 4M TPM / 150K RPD |
| Gemini 3 Flash | 5 RPM / 250K TPM / 20 RPD | 1K RPM / 2M TPM / 10K RPD |
| Gemini 3.5 Flash | 5 RPM / 250K TPM / 20 RPD | 1K RPM / 2M TPM / 10K RPD |

The snapshot source is the supplied `Tier 0 (kostenlos).mhtml` and `Tier 1
(Billing).html`; refresh it when AI Studio changes the active project limits.

`fleet_gemini_bootstrap_plan` remains a secret-free compatibility dry-plan
helper only. It does not create the retired D/E/F series; runtime activation
comes from populated `The_Hive_N` entries in the private token file. Keys
1–10 belong to one billing account with one project per key; keys 11–20 and
21–30 are reserved for the next two accounts and are activated only when
their values exist. The optional installer uses
only the official stable package channel:

```sh
NPM_CONFIG_PREFIX="$HOME/.local" ./scripts/install-gemini-cli
"$HOME/.local/bin/gemini" --version
```

The installer refuses an unwritable system NPM prefix instead of escalating
privileges; set an explicit user-owned `NPM_CONFIG_PREFIX` as above.

Gemini jobs use an agent-private `HOME`/`GEMINI_CLI_HOME`, stdin-only task
input, bounded `stream-json` stdout/stderr, process-group cancellation, and
role-specific approval (`plan` for Exploriererinnen, `auto_edit` for
Arbeitsbienen). The CLI is explicitly put into headless mode with an empty
`--prompt`; the actual task remains stdin-only. They do not use `yolo`, `-p -`,
or Codex TUI markers. The assignment response is bounded and parsed. Prompts,
credentials, tool events, and raw output stay out of persistent metadata;
process output remains bounded.
Productive headless assignments accept up to 7200 seconds (120 minutes) per
call; the default remains 600 seconds.

For Gemini series whose registry model is `auto`, Masterjet pins the
headless CLI to `gemini-3.1-flash-lite`, the low-cost/high-RPM default for
structured Bauplan audits. A heavier model is used only when it is explicitly
configured for that series.

Every Gemini API probe or headless job also takes a persistent per-project
request reservation. Reservations allow only one active request, enforce a
60-second minimum spacing across processes and restarts, and apply an
exponential cooldown after a verified 429 (starting at 15 minutes, capped at
24 hours). The private state is stored in `fleet/rate-limits.json`; malformed
state fails closed and is quarantined rather than permitting another request.

The GTK-free `fleet_control` view model and `control_center` controller enforce
the same bounds and generation checks as the server; the optional GTK3 page is
loaded lazily so headless imports remain display-free. The Cinnamon adapter uses
snapshot schema v3, at most 26 series and 25 visible rows per series page;
limited rows are status-only. Real provider credentials, account probes,
Ollama resource admission, and desktop-session acceptance remain explicit
local gates. Ollama series remain `simple_only` and reject complex or
repository-changing tasks. Their configured separate two-agent resource cap
and host-pressure gates are enforced; the global ten-Bee cap remains an
additional upper bound.

## Tools

- `agent_start`: start selected Agentinnen; `all`/series selectors require
  `allow_broad_selector=true` when they resolve to more than 6 Agentinnen
- `agent_status`: structured status, response state, and limit classification
  without raw output
- `agent_lease_status`: data-sparse lease state for selected Agentinnen
- Broad read-only selectors on `agent_status`, `agent_lease_status`,
  `agent_skills`, `agent_skill_match`, and `agent_capabilities` are paged with
  `agents_limit`/`agents_offset`; the default page size is 30 Agentinnen and
  responses include `total_count` plus `truncated` metadata.
- `agent_claim`: claim or renew one Agentin, retrying forever by default when
  she is busy; explicit claims may recover stopped orphan leases after grace
- `agent_release`: release this MCP client's Agentin claim; force only after
  checking status
- `agent_wait`: wait for activity/stop/limit metadata without raw output,
  defaulting to 120 seconds and capped at 10 minutes per call
- `fleet_watchdog`: request a report from idle Agentinnen, wait a grace window,
  then optionally interrupt, stop, or release without raw output
- `usage_watchdog`: synchronize codex-usage limit blocks with local Agentin
  state, stopping blocked running Agentinnen and clearing the local block
  marker once the codex-usage watchdog releases them
- `agent_send`: send text to one running Agentin
- `agent_interrupt`: send Ctrl-C to one running Agentin
- `agent_stop`: stop selected Agentinnen; `all`/series selectors require
  `allow_broad_selector=true` when they resolve to more than 6 Agentinnen
- `agent_safe_tail`: explicit capped, ANSI-stripped, redacted excerpt; refuses
  active leases held by other clients before reading pane or log output; log
  source reads only regular raw-log files
- `agent_skills`: data-sparse skill inventory without file contents
- `agent_skill_match`: check whether one or all Agentinnen have a named skill
- `agent_capabilities`: summarized model, skill, and policy capabilities with a
  bounded plugin page
- `agent_scope_check`: verify write paths stay inside assignment scope
- `agent_assign`: structured, skill-aware assignment with explicit boundaries
- `agent_assign_readonly`: shortcut for read-only Exploriererin assignments
- `agent_assign_live_data`: shortcut for read-only Web-/Live-Daten assignments
  that require current sources or an explicit tooling/access-limit report
- `agent_assign_write`: shortcut for Arbeitsbiene write assignments
- `agent_assignments`: data-sparse assignment audit log
- `agent_last_assignment_status`: latest assignment metadata for one Agentin
- `agent_report_request`: ask one Agentin for a concise report
- `agent_assignment_report`: read a capped redacted excerpt for a known assignment
- `agent_selector_policy`: show or set the ordinal selector policy, for example
  `a,b` or `a,b,c`
- `agent_selector_preview`: preview numeric selector mapping without mutating
  state
- `agent_selection_preview`: preview real fleet candidates through the
  read-only Selection-/Admission-Kern; Shadow plans but never executes.
  Enforced remains closed until authoritative Hive callbacks and an
  operation-specific executor are supplied; `ServerAdmissionRuntime` provides
  the fail-closed boundary but does not execute operations

The local `codex_master.admission` module now supplies that reservation
boundary as an in-process, fail-closed contract: immutable records bind work
version, grant/scope digests, lease expectation, and the selected resource;
state changes use a revision CAS, reservation TTLs are bounded to 30–120
seconds, and `public()` removes account keys, scope paths, and other private
bindings. Scope overlap, agent/account/account-model capacities, and
read/read versus write overlap are checked atomically. `FileAdmissionStore`
adds a private lock plus atomic state replacement for fresh-process recovery;
malformed, oversized, or symlinked state fails closed. It performs no
provider, lifecycle, lease, or network mutation and is not yet wired into
Enforced execution.

`codex_master.selection_service.SelectionService` is the next local
orchestration layer. It delegates preview to the same deterministic planner,
revalidates before an injected runtime call, retries at most three times with
50/100/200 ms backoff, compensates failed attempts, and reconciles crash
evidence without re-executing. `codex_master.admission_runtime.ServerAdmissionRuntime`
now provides the fail-closed server boundary: authority, repository, and
canonical scope callbacks must come from authoritative Hive records; existing
Fleet account, model, Usage, lease, process-identity, auth, and runner-config
checks are attached in a fixed order. Missing Hive bindings, stale admissions,
malformed gate evidence, or callback errors deny the runtime, and successful
revalidation is single-use per admission revision. The adapter itself never
claims, starts, assigns, or calls a provider. Its private cross-process store
is rooted at the state-local `admission-state.json`/lock pair when an auto
execution path explicitly requests `current_admission_store()`; productive
Enforced execution remains closed until the authoritative Hive callbacks and
an operation-specific executor are supplied.

Applet status exposes bounded `fleet_snapshot_degraded` and
`watchdog_snapshot_degraded` flags when its read-only sources are unavailable.
An exhausted Usage-v2 window whose verified reset is already past no longer
blocks the account; future or unknown resets remain fail-closed.

### Hive control plane

The `codex_master.hive` package now contains the bounded control-plane
foundations: strict public configuration, private state, principals and
execution bindings, repository/authority checks, typed messages and dispatch
state machines, append-only decisions, provenance-aware memory, a DP work
queue, and a single admission boundary. The `codex_master.selection` package
is a compatibility boundary around the existing deterministic planner and
adds typed model-policy, task-classification, source, fairness-state, and
passive-anchor contracts without introducing a second selector.

Hive status, validation, migration, and Selection diagnostics are exposed as
read-only MCP tools. Missing authoritative Work-/Grant-/Repository-/Scope-
and Lease evidence remains fail-closed; no Hive diagnostic tool claims,
starts, assigns, or invokes a provider.

Operational details are documented in [`docs/account-aware-selection.md`](docs/account-aware-selection.md),
[`docs/operations/hive-operations.md`](docs/operations/hive-operations.md),
[`docs/operations/selection-operations.md`](docs/operations/selection-operations.md),
[`docs/security/hive-security.md`](docs/security/hive-security.md),
[`docs/security/selection-privacy.md`](docs/security/selection-privacy.md), and
[`docs/migration/hive-selection-migration.md`](docs/migration/hive-selection-migration.md).
Public, secret-free configuration examples live in
[`examples/`](examples/): agent classes, Hive mode, and model policy.
- `worktree_create_for_agent`: create an isolated git worktree for one Agentin
- `worktree_status`: capped git status and worktree metadata
- `integration_status`: repo status, diff stat, and recent assignment metadata
- `commit_ready_check`: fixed readiness checks for integration/commit
- `master_app_bridge_status`: App Bridge manifest and connector-ID status
- `master_plugin_status`: plugin packaging, plugin-cache drift, App Bridge, and
  MCP registration status
- `master_namespace_status`: diagnose `codex-master-mcp` registration, startup,
  plugin-cache drift, and `tools/list` visibility for new clients
- `master_release_status`: diagnose release drift across package version, plugin
  manifest version, local tags, and GitHub releases
- `master_watchdog_status`: diagnose systemd Fleetwatchdog health, installed
  unit hardening, and aggregate security-score status
- `master_timeout_policy`: report effective timeout and polling policy for MCP
  startup, Agentin claim retry, Agentin wait, productive headless assignments,
  watchdog supervision, and hidden CLI lease identity source
- `master_applet_status`: bounded read-only snapshot for 1–6 concrete Agentinnen;
  used by the Cinnamon applet and available as `applet-status` in the CLI
- `agent_pool_validate`: validate a machine-readable Agentinnen pool spec
- `agent_pool_install`: install or refresh sleeping Agentinnen homes from a spec
- `agent_pool_status`: inspect data-sparse pool installation counts
- `agent_pool_copy_auth`: explicitly copy one source `auth.json` to many
  installed Agentinnen, dry-run by default
- `agent_pool_destroy_pool`: guarded removal of installed Agentinnen homes
- `agent_doctor`: structured diagnostics without raw output
- `agent_selection_options`: account- and authority-filtered first-round offer
  containing only valid class/lifecycle/model/reasoning combinations
- `fleet_account_list`, `fleet_gemini_bootstrap_plan`, `fleet_series_list`,
  `fleet_account_upsert`, `fleet_account_set_secret`, `fleet_account_disable`,
  `fleet_account_probe`, `fleet_account_delete`, `fleet_provider_models`,
  `fleet_series_plan`, `fleet_series_apply`, `fleet_series_disable`, and
  `fleet_series_delete`: bounded Fleet account/provider/series management;
  secret input is stdin-only and mutations use generation CAS

`/mcp` should show `codex-master-mcp` only in the Teamleiterin/main Codex
instance. Managed Agentinnen intentionally do not receive Masterjet MCP tools;
they are controlled from outside and may only use native Subagentinnen when an
assignment explicitly allows it.
`tool_search` is not authoritative for the local stdio MCP namespace; use
`/mcp` in the affected Codex client or `namespace-status` from this repo.
`plugin-status` and `namespace-status` also report whether the repo plugin
manifest version is installed in the local plugin cache, without returning cache
paths.
For `namespace-status`, top-level `ok` means the MCP server, local plugin cache,
active Codex client config, and active `CODEX_HOME` context are ready.
`mcp_server_ready`, `plugin_cache_ready`, `client_config_ready`, and
`active_home_ready` remain separate for isolating server startup from stale
client/plugin state, a mismatched config, or a managed Agentin home.
`running_process_summary.namespace_visibility` reports only aggregate client
home categories so sibling Codex sessions can identify when custom homes need
their own MCP config or when managed Agentin homes are expected not to expose
Master MCP tools.

## Local CLI

### Zentraler Klassen-/Lifecycle-/Modellresolver

Vor dem ersten Start oder Assignment einer Serie fragt das anfordernde Modell
`agent_selection_options` fuer eine konkrete Ziel-Agentin ab. Die Antwort
enthaelt nur aktuell erlaubte Klassen, Lifecycles, Modelle, Reasoning-Stufen und
deren gueltige Kombinationen. Das Angebot ist advisory und reserviert nichts.
Seine `generation` kann bei Folgeaufrufen als `known_generation` mitgegeben
werden; `options_changed` meldet account- oder katalogbedingte Aenderungen.
Beim ersten Angebot fuer eine Teamleiterin muss sichtbar genau ein legales
Tupel erscheinen: `class=teamleiterin`, `lifecycle=persistent`,
`model=gpt-5.6-terra`, `reasoning=xhigh`. Fuer die Policy ist `xhigh` zugleich
Minimum und Maximum. Andere Teamleiterin-Tupel duerfen nicht angeboten werden.

`agent_start`, `agent_assign` und die Assignment-Shortcuts geben ihre optionalen
Felder `class`, `lifecycle`, `model`, `reasoning_effort` und `complexity` an
denselben Resolver. Danach wird keine zweite Auswahl-Policy angewendet.
Oeffentliche Lifecycles sind `ephemeral`, `binding` und `persistent`;
`invocation` bleibt als Eingabealias erlaubt und wird als `ephemeral`
zurueckgegeben.

Kompatible explizite Angaben bleiben erhalten. Klassenprofil, Lifecycle,
Modellfaehigkeiten, accountbezogene Verfuegbarkeit sowie Reasoning-Minimum und
-Maximum sind harte Grenzen. Fehlt die Klasse, wird eine passende delegierbare
Nicht-Leitungsklasse gewaehlt; Leitungsklassen werden nie automatisch
hochgestuft. Fehlt der Lifecycle, gilt das Klassenprofil. Defaults fuer
Arbeiterinnen:

- einfacher Schreibjob plus `ephemeral`: `gpt-5.3-codex-spark`/`low`
- Read-only oder nicht einfacher Schreibjob plus `ephemeral`:
  `gpt-5.6-luna`/`medium`
- `binding`: `gpt-5.6-luna`/`high`
- `persistent`: `gpt-5.6-luna`/`xhigh`; `xhigh` ist hier zugleich Minimum

Ist Spark fuer den Account nicht verfuegbar oder verwirft die Task-Pruefung ihn,
faellt der Default auf Luna zurueck. Spark ist nur der Default fuer einen
einfachen Schreibjob ohne Modellwunsch. Ein fuer eine Arbeiterin explizit
angefordertes unbekanntes oder nicht verfuegbares Modell faellt sicher auf
`gpt-5.6-luna`, nie auf Spark; ein kompatibles explizites Effort bleibt erhalten
oder wird an Ersatzmodell sowie Klassen-/Lifecyclegrenzen geklemmt.
Klassenfremde oder zu schwache Angaben werden ebenfalls innerhalb der harten
Grenzen ersetzt; Gottbiene und Koenigin bleiben Sol-gebunden. `selection.fallback`,
angeforderter und effektiver Wert sowie stabile `reason_codes` liefern die klare
Fehl-/Fallbackmeldung. Das anfordernde Modell kann danach abbrechen oder mit
einer anderen angebotenen Kombination neu anfragen. Gueltige Aufstiege Spark ->
Luna -> Terra -> Sol bleiben innerhalb der Klassen- und Effortgrenzen moeglich.
`ultra` ist nie erlaubt.

Teamleiterin ist fest persistent und nutzt exakt `gpt-5.6-terra` mit `xhigh`;
`xhigh` ist fuer sie zugleich Minimum und Maximum. Ein erforderliches Modell
oder Effort, das nicht verfuegbar ist, ist ein harter Fehler ohne Fallback.
`required_model_unavailable:gpt-5.6-terra` beziehungsweise
`required_model_effort_unavailable:gpt-5.6-terra:xhigh`.
Das gilt insbesondere fuer die Teamleiterin: Start und Assignment teilen den
zentralen Resolver und duerfen niemals auf Sol, Luna, Spark oder ein anderes
Effort ausweichen.

Leitungsklassen sind fest persistent und stellen sich beim ersten echten
Userkontakt mit Namen vor: Gottbiene nutzt `gpt-5.6-sol`/`max`, Koenigin nutzt
`gpt-5.6-sol`/`xhigh`, und Teamleiterin nutzt exakt
`gpt-5.6-terra`/`xhigh`. Fuer Koenigin, Teamleiterin und alle Arbeiterklassen
ist `xhigh` absolute Obergrenze; nur die Gottbiene darf `max` nutzen.

Der kanonische Betriebsablauf steht in
[Selection Operations](docs/operations/selection-operations.md). Die
versionierten Kataloge [`codex-agent-classes.json`](codex-agent-classes.json)
und [`codex-model-policy.json`](codex-model-policy.json) bleiben autoritativ;
README und Skill definieren keine zweite Auswahl-Policy.

### Ressourcenbewusste Spawn-Angebote

`agent_spawn_offers` ist ein read-only MCP-Hinweis fuer eine moegliche lokale
Kapazitaet. Beispiel fuer einen MCP-`tools/call`:

```json
{"name":"agent_spawn_offers","arguments":{"required_slots":1}}
```

Gleiches CLI-Kommando aus diesem Worktree:

```sh
PYTHONPATH=src python -m codex_master.server spawn-offers --required-slots 1
./bin/codex-master-mcp spawn-offers --required-slots 1
```

`PYTHONPATH=src` ist fuer Python-Aufrufe dieses Worktrees erforderlich: eine
lokale editable Installation kann auf einen anderen Quellstand zeigen.

Ein Offer ist advisory, gilt 5 Sekunden und reserviert nichts
(`reservation: "none"`). `start` prueft freie Gesamtslots vor einem neuen
tmux-Start unter dem Admission-Lock erneut. Ohne belastbare Gesamtzahl bleiben
Offers leer; die data-sparse Antwort enthaelt nur Reason-Codes, keine
`/proc`-Inhalte, tmux-Ausgabe, lokalen Pfade oder Environment-Texte. Sie ist
retryable mit 15 Sekunden Wartehinweis.

Temporäre Grenzen fuer einen neuen Start:

- Ressourcendruck-Grenzen bleiben mit ihren bisherigen Werten konfiguriert und aktiv: CPU, Load, I/O-Wait und RAM können Spawn fail-closed blockieren.
- die konfigurierte Ollama-Zweiergrenze bleibt erhalten und wird vor der globalen Zehnergrenze durchgesetzt
- hoechstens `10` Bienen insgesamt; laufende Masterjet-Sessions sowie aktive und unbestaetigte native Subagentinnen zaehlen zusammen
- ab `10` Bienen wird jede weitere Biene hart abgewiesen
- `required_slots` liegt zwischen 1 und 10

Verweigerte Admission-Antworten enthalten neben stabilen `reason_codes` eine
strukturierte `errors`-Tabelle. Jeder Eintrag liefert `code`, `title`,
`explanation`, `rule` und `action`; Rohmetriken oder lokale Zustandsdaten werden
nicht aufgenommen.

| Code | Bedeutung |
|---|---|
| `running_agent_limit` | Globale Zehnergrenze bereits erreicht. |
| `insufficient_slots` | Anfrage passt nicht vollstaendig in verbleibende Gesamtslots. |
| `session_metrics_unavailable` | Masterjet kann Gesamtzahl nicht belastbar bestimmen. |
| `policy_invalid` | Konfigurierte Werte oder Enforcement-Flags sind ungueltig. |
| `cpu_metrics_unavailable` | CPU-Evidenz fehlt; relevant, wenn Druck-Enforcement aktiv ist. |
| `memory_metrics_unavailable` | Speicherevidenz fehlt; relevant, wenn Druck-Enforcement aktiv ist. |
| `cpu_pressure_high` | Aktive CPU-Grenze ueberschritten. |
| `io_pressure_high` | Aktive I/O-Wait-Grenze ueberschritten. |
| `memory_pressure_high` | Aktive Speichergrenze unterschritten. |
| `ollama_concurrency_limit` | Konfigurierte aktive Ollama-Zweiergrenze erreicht. |
| `ollama_simple_task_only` | Aufgabe verletzt Ollama-Capability-Gate. |

`CODEX_MASTER_SPAWN_PRIORITY` ist einzige Spawn-Environment-Konfiguration.
Sie ist eine kommagetrennte Prioritaetsliste (Default `mcp_host`), wird nur als
Daten gelesen, dedupliziert und niemals als Shell-Befehl oder Netzwerkziel
ausgefuehrt. Ihr Text wird nicht in Antworten gespiegelt. Aktuell kann nur der
exakte lokale Route-Wert `mcp_host` ein Offer erzeugen. `developer_vm` und
`sandbox` sind nicht angeboten, selbst wenn sie in dieser Liste stehen; es gibt
keine Remote-Ausfuehrung in dieser Version.

Ein Offer erzeugt keine Lease, keine Meta-Datei und keinen Assignment-Audit-
Eintrag. Auth-, Scope-, Routing-, Modell-, Nutzungs- und bestehende Admission-
Gates bleiben beim eigentlichen Start beziehungsweise bei Assignments wirksam.
Ein sauberer tmux-Zustand ohne Server oder Sessions zaehlt als null laufende
Agentinnen. Messfehler, `/proc`-Fehler und alle anderen tmux-Fehler fail-closed;
ihre oeffentlichen Fehler bleiben begrenzt und redigiert.

Native Subagentinnen melden Starts und Stops an den Masterjet. Aktive und
unbestaetigte Eintraege zaehlen deshalb in jede folgende Slotentscheidung ein.
Die Assignment-Prompt-Policy verlangt den frischen Gesamtcheck vor jedem
weiteren Spawn. Ein Modell, das diesen MCP-Pfad umgeht, kann der Masterjet ohne
Codex-eigenen Pre-Spawn-Hook weiterhin nicht technisch intercepten.
`developer_vm` darf erst offerable werden, wenn alle
folgenden Voraussetzungen erfuellt sind:

- real reachability/health probe against the actual VM
- authenticated transport and host-key verification/pinning
- distributed leases/reservations across hosts
- bounded remote execution (timeouts and bounded output)
- end-to-end integration testing against the real target

Bis dahin bleibt ein VM-Backend vollstaendig weggelassen.

```sh
cd /home/teladi/codex-master
python3 -m codex_master.server install          # create ~/.local/bin/codex-master-mcp + codex mcp add
python3 -m codex_master.server doctor          # smoke check (codex, tmux, state path, JSON result)
python3 -m codex_master.server uninstall       # remove mcp registration and local symlink
python3 scripts/codex-master-cinnamon-applet install --dry-run
python3 scripts/codex-master-cinnamon-applet install --no-reload
python3 scripts/codex-master-cinnamon-applet verify

python3 -m codex_master.server start both --cwd /home/teladi/codex-master
python3 -m codex_master.server status
python3 -m codex_master.server selector-policy
python3 -m codex_master.server selector-policy --series a,b,c
python3 -m codex_master.server selector-preview --limit 6
python3 -m codex_master.server selection-preview --series d --task-kind simple --admission-mode shadow --sp1a --limit 8
python3 -m codex_master.server lease-status all --agents-limit 30
python3 -m codex_master.server claim b --forever --poll-interval-seconds 30
python3 -m codex_master.server claim b --no-wait
python3 -m codex_master.server claim b --no-recover-stopped
python3 -m codex_master.server wait a --timeout-seconds 120 --poll-interval-seconds 30
python3 -m codex_master.server watchdog active --idle-seconds 60 --poll-interval-seconds 15 --report-grace-seconds 15 --action stop --manage-unclaimed --quiet
python3 -m codex_master.server capabilities all --agents-limit 30
python3 -m codex_master.server skills all --agents-limit 30
python3 -m codex_master.server skills a --include-names --limit 20 --names-offset 20 --plugins-offset 20 --plugins-limit 20
python3 -m codex_master.server skill-match all codex-security:security-scan --agents-limit 30
python3 -m codex_master.server scope-check --scope src/codex_master --write-path src/codex_master/server.py
python3 -m codex_master.server assign-readonly a --skill codex-security:security-scan --scope src/codex_master/server.py --task "Pruefe nur lesend und berichte knapp."
python3 -m codex_master.server assign-live-data a --task "Wie ist das Wetter gerade in Berlin?" --live-data-topic "Wetter Berlin heute"
python3 -m codex_master.server assign-write b --scope .github/workflows --write-path .github/workflows/ci.yml --task "Haerte nur die CI-Datei."
python3 -m codex_master.server assignments all --limit 20
python3 -m codex_master.server last-assignment a
python3 -m codex_master.server assignment-report a ASSIGNMENT_ID --source pane --lines 40 --chars 4000
python3 -m codex_master.server integration-status
python3 -m codex_master.server commit-ready-check
python3 -m codex_master.server app-bridge-status
python3 -m codex_master.server plugin-status
python3 -m codex_master.server namespace-status
python3 -m codex_master.server release-status
python3 -m codex_master.server watchdog-status
python3 -m codex_master.server timeout-policy
python3 -m codex_master.server fleet-recovery-status
python3 -m codex_master.server fleet-recovery-retry
python3 -m codex_master.server pool validate --spec codex-agent-pool.json
python3 -m codex_master.server pool install --spec codex-agent-pool.json --target-dir "$HOME/.codex-agents" --codex-bin /usr/local/bin/codex
python3 -m codex_master.server pool status --spec codex-agent-pool.json
python3 -m codex_master.server pool copy_auth --spec codex-agent-pool.json --from-agent a1 --to a-series
python3 -m codex_master.server pool destroy_pool --spec codex-agent-pool.json --yes
python3 -m codex_master.server send a "Kurzer Auftrag"
python3 -m codex_master.server release b
python3 -m codex_master.server tail a --source pane --lines 20 --chars 2000
python3 -m codex_master.server stop both
```

## Agentinnen Pool Spec

The repo contains a generic, machine-readable `codex-agent-pool.json` plus
`schemas/codex-agent-pool.schema.json`. The current installed native pool uses
five A homes, three B homes, and three C homes. `a1` and `b1` remain the
authenticated source homes; b92 is a separately preserved active home and is
shown in the merged fleet inventory. Gemini series are managed through the
Fleet registry and are not part of this native pool spec.
Pool spec reads accept only regular UTF-8 JSON files, reject symlinked or
oversized spec files, and keep spec paths out of public error responses.
Pool validation returns only counts and state markers for series, aliases, and
authenticated Agentinnen; concrete names are not echoed.
Pool install also keeps generated `codex` wrappers and `config.toml` files as
per-Agentin regular files, replacing symlinked entries without touching their
targets, validates runtime directories as real directories, and writes a
regular installed-pool marker. Pool status reports `ok` only when the marker,
all expected homes, wrappers, configs, and required shared-asset links are
present and valid. Shared-asset diagnostics are counts only; local link targets
and pool paths are not returned. Pool status also returns series counts without
echoing concrete series names.

The spec is only the map. The actual auth material is still the per-home
`auth.json`, for example `~/.codex-agents/a1/auth.json`. Normal install never
copies auth material.

Two install paths are supported:

```sh
./bin/codex-master-mcp pool install --spec codex-agent-pool.json --target-dir "$HOME/.codex-agents"
./scripts/install-agent-pool --spec codex-agent-pool.json --target-dir "$HOME/.codex-agents"
```

Use `--codex-bin` when the Codex CLI binary is not `/usr/local/bin/codex`.
Normal install never copies auth material. For bulk auth propagation, run
`pool copy_auth` first without `--yes` to inspect counts, then repeat with
`--yes` when intentional. `copy_auth` copies only `auth.json`, skips the source
Agentin when she is part of the target selector, requires the source Agentin home
to be a real directory, and never returns auth content, the source Agentin id, or
the requested target selector.

Do not use symlinks or hardlinks for `auth.json` in the normal pool model.
Auth files are small; copies keep each Agentin isolated. Symlinks cross the
no-follow trust boundary, and hardlinks share one inode across multiple
Agentinnen.

See `docs/agent-pool.md` for the full command set and `docs/auth-copy.md` for
the auth-copy safety model.

The Cinnamon installer copies the applet into the per-user Xlet directory with
an atomic swap, one validated rollback tree, a private operation lock, and
bounded source/target verification. `install --dry-run` performs no filesystem
or D-Bus mutation; `--no-reload` is useful for CI and temporary-home smoke
tests. `verify` additionally checks the running Cinnamon Xlet when a desktop
session is available.

## Cinnamon Applet: Flottenmanagement

`codex-master@H234598` is the P3/P3a read-only status applet. Its visible panel
title is always `Flottenmanagement`. It explicitly requests applet status
schema v2; schema v1 remains available for older callers.

Each schema-v2 refresh uses one bounded tmux session inventory. Every known
running codex-master Agentin is discovered automatically and shown, up to the
fixed six-row limit. Foreign tmux sessions are ignored. `tracked-agents` no
longer defines the visible fleet: it only pins sleeping Agentinnen into rows
left free by active Agentinnen. Its `a1,b1` default therefore does not limit
automatic discovery. More than six active managed Agentinnen produce a bounded
overflow marker instead of an unbounded menu.

Native Codex-Subagentinnen are not mixed with managed tmux Agentinnen. Official
`SessionStart`, `SubagentStart`, `SubagentStop`, and `SessionEnd` hooks maintain
a private bounded register. The applet renders that register only in the
separate `Native Bienen (N)` submenu, using six fixed, non-reactive child rows.
Native rows are status-only and contain no action or context token.

The applet starts at most one bounded `codex-master-mcp applet-status` child
process, never invokes a shell, and currently exposes no start, stop,
interrupt, auth, or lease mutation. Applet actions belong to later milestone
P4.

The status model keeps three concerns separate:

- `activity_state`: running, sleeping, mixed, or unknown;
- `backend_state`: ok, degraded, or unavailable;
- `control_state`: ready, blocked, mixed, or unknown.

A sleeping Agentin is normal and does not by itself degrade backend health.
Failed refreshes retain the last valid snapshot and mark it as stale. Responses
contain fixed state fields and counts only; prompts, logs, process IDs, paths,
lease owners, lease IDs, and raw output are not returned.

The four applet settings are:

- `tracked-agents`: comma-separated `a1` through `c100`; 1–6 concrete IDs to
  pin as sleeping rows when automatic active discovery leaves capacity,
  case-normalized and deduplicated; default `a1,b1`;
- `refresh-on-open`: refresh when opening the menu; default on;
- `background-refresh`: opt-in periodic refresh; default off;
- `refresh-interval-seconds`: 15–3600 seconds; default 60.

Malformed agent, switch, or interval values show a configuration error, fall
back to safe defaults, disable background work, and never reach the process
argv. Finite refresh intervals outside the allowed range are clamped to
15–3600 seconds. The menu contains a manual refresh, applet administration,
one summary, at most six managed rows, and the separately bounded Native-Bienen
submenu.

Only the Koenigin may restart or reload Masterjet, install it, or synchronize
the plugin cache. Other roles may inspect and verify state and recommend these
actions to the Koenigin, but must not execute them.

Install MCP/plugin and applet with the repository-owned installers:

```sh
./bin/codex-master-mcp install
./scripts/codex-master-cinnamon-applet install --dry-run
./scripts/codex-master-cinnamon-applet install
./scripts/codex-master-cinnamon-applet verify
```

The complete CLI reference is the repository manpage
[`codex-master-mcp(1)`](man/man1/codex-master-mcp.1). Build deterministic
compressed output without installing it, or render the source directly:

```sh
./scripts/codex-master-manpage build --output-dir /tmp/codex-master-man
groff -man -Tutf8 man/man1/codex-master-mcp.1
```

`codex-master-mcp install` synchronizes the plugin, including the regular
`hooks/hooks.json`, `hooks/native_spawn_admission.py`, and
`hooks/native_bee_event.py` files, into the personal plugin cache. It does not
and must not alter Codex hook-trust state. After installation, open a new Codex
session, run `/hooks`, inspect the five `codex-master` definitions, and
explicitly trust them: one blocking `PreToolUse` admission hook plus four
lifecycle hooks. Until that manual step succeeds, do not claim that native
spawn admission or Native-Bienen lifecycle coverage is active.

Rollback the active applet tree with:

```sh
./scripts/codex-master-cinnamon-applet rollback
```

`install` stages and hashes regular non-hardlinked source files, rejects
symlinked source/target paths, reloads only this UUID through Cinnamon's
`ReloadXlet`, and restores and reloads the previous tree if deployment fails.
`verify` requires byte-identical installed files and a running UUID from
`GetRunningXletUUIDs applet`. `rollback` requires validated installed and
rollback trees, but not an intact repository source. It fails closed when a
required tree is missing or unexpected. Install, verify, and rollback are
serialized by a private per-UUID lock. `--no-reload` is available for
controlled offline install/rollback tests. No command uses `Eval` or restarts
Cinnamon globally.

Useful diagnostics:

```sh
./bin/codex-master-mcp applet-status --schema-version 2
gdbus call --session --dest org.Cinnamon --object-path /org/Cinnamon \
  --method org.Cinnamon.GetRunningXletUUIDs applet
journalctl --user -b | grep -F codex-master@H234598
```

An `unavailable` or stale applet state means the bounded read-only refresh
failed. Verify the installed files and CLI first; do not interpret ordinary
`sleeping` activity as a backend failure.

## Install-Contract (CLI)

`install`
- creates `~/.local/bin/codex-master-mcp` as symlink to `bin/codex-master-mcp`
- verifies that the repo wrapper can answer an MCP `initialize` probe before
  registering it with Codex
- verifies that the installed command path also answers the same probe before
  registration
- registers the command via `codex mcp add codex-master-mcp -- <link>`
- ensures the active Codex MCP config has `startup_timeout_sec = 120`
- syncs the personal `codex-master` plugin cache from a runtime allowlist
  (`.codex-plugin`, `.app.json`, `.mcp.json`, `bin`, `docs`, `examples`,
  `schemas`, `scripts`, `skills`, `src`, `systemd`, README,
  `codex-agent-pool.json`, and package metadata) while excluding `.git`, tests,
  bytecode, test caches, hidden files, editor swap files, and backup/patch
  leftovers
- rejects hardlinked plugin source files and keeps only the current plus the
  most recent valid cached plugin versions, without pruning invalid or symlinked
  cache entries
- copies regular plugin-cache source files through no-follow file descriptors
  and verifies source identity after opening, so a source swap cannot redirect
  cache contents
- creates nonce-suffixed plugin-cache temp directories and never removes a
  pre-existing temp directory that this sync did not create
- refuses to register the Master MCP from a managed Agentinnen `CODEX_HOME`
- requires the install-path parent chain to be real directories, not symlinks
- creates or replaces the install symlink via an atomic same-directory
  temporary symlink and directory-fd-bound rename
- treats broken, looping, or unreadable install symlinks as non-matching instead
  of crashing while resolving them
- returns JSON without agent output, install path, repo-wrapper target path, or
  plugin-cache paths
- accepts `--no-plugin-cache` only for explicit diagnostic installs that should
  leave the personal plugin cache untouched

`uninstall`
- unregisters from `codex mcp remove codex-master-mcp`
- removes `~/.local/bin/codex-master-mcp`
- requires the install-path parent chain to be real directories when removing
- removes the install symlink through the verified parent directory fd, so a
  parent swap after validation cannot redirect the unlink
- leaves broken, looping, or unreadable install symlinks in place unless they
  resolve to the repo wrapper
- returns JSON and no raw secret material

`doctor`
- checks availability of required tooling (`codex`, `tmux`) and MCP state directory
- reports a structured `checks` object
- verifies the installed MCP command with a data-sparse `initialize` probe
- reports whether the active Codex MCP registration has
  `startup_timeout_sec >= 120`
- reports whether the active `CODEX_HOME` looks like the main default home, a
  managed Agentinnen home, or a custom home without returning the path
- hides local wrapper, install, Agentin home, and Agentin runner paths behind
  state/category fields while preserving existence and health checks
- reports raw-log retention counts and sizes without returning managed raw-log
  directory paths
- warns, without returning file paths, when the installed MCP points at this
  repo while the worktree has tracked or untracked changes
- reports broken, looping, or unreadable install symlinks as a failed
  `installed_symlink` check with an unreadable target marker
- treats stopped Agentinnen as informational session state, not as a failed
  health check
- redacts known secret shapes in output

`watchdog`
- classifies idle state from structured `status` metadata and raw-log metadata
  only; it does not call `tail` or return Agentin output
- defaults to `idle_seconds=60`, `poll_interval_seconds=15`,
  `report_grace_seconds=15`, and `action=interrupt`
- always asks the Agentin for a concise report before `interrupt`, `stop`, or
  `release`
- stores only a metadata marker with request time, assignment ID, planned
  action, and raw-log counters; no prompt text, responses, or raw logs are
  stored in the marker
- skips active leases held by other clients; `--manage-unclaimed` may supervise
  only unclaimed or expired leases in addition to this server's own lease
- supports `--quiet` for systemd runs; successful watchdog passes produce no
  JSON output, while failures still use the normal CLI error path
- is installed as an optional `systemd --user` top layer through
  `systemd/user/codex-master-watchdog.service` and
  `systemd/user/codex-master-watchdog.timer`
- the user service runs with conservative hardening directives:
  empty `CapabilityBoundingSet`, private keyring/tmp/devices, a read-only bind
  of the user's tmux socket directory, kernel and clock protections, read-only
  system hierarchy, explicit write access only to the managed state and user
  runtime directories, no IP sockets, no namespaces,
  `NoNewPrivileges`, `MemoryDenyWriteExecute`, native syscall architecture,
  and `UMask=0077`; it intentionally keeps normal user home read access because
  the watchdog needs Codex config, tmux IPC, and managed state files
- `codex-usage` stores its current snapshots under
  `~/.local/share/codex-usage/current/<account>.json` by default; the reader
  accepts the older `snapshots/` layout only when the current file is absent
  and fails closed when an existing current file is malformed. `usage_watchdog`
  normalizes current 5-hour/weekly windows into secret-free Usage-v2 data,
  writes the local codex-usage block marker, and refuses new
  `agent_start`/claim flows while a future reset window remains active; past
  verified resets clear the block and unknown resets remain fail-closed

`watchdog-status`
- reports whether the systemd timer is active and whether the last service run
  succeeded, without returning raw `systemctl` output
- checks that the installed watchdog service and timer match the repo copies
  and that the service still contains the required hardening directives and
  watchdog flags
- parses only the aggregate `systemd-analyze security` exposure score and
  level; raw analyzer output and local unit paths are not returned

`goddess report run` processes all eligible UTC report buckets in chronological
order, backfills up to 24 hours, and retries buckets that were not finalized.
For hourly operation, enable the hardened optional user timer:

```sh
systemctl --user daemon-reload
systemctl --user enable --now codex-master-goddess-report.timer
```

`timeout-policy`
- reports that `agent_claim` retries forever by default for busy fremde Bienen,
  while finite claim waits are still accepted without a 600 second cap
- reports that claim polling defaults to 30 seconds and is capped at 900 seconds
- reports stopped foreign lease recovery defaults for explicit claims: only
  stopped Agentinnen, no managed-home process, and sufficient idle evidence
- keeps `agent_wait` separate as a bounded activity wait: default 120 seconds,
  maximum 600 seconds
- reports productive headless assignments with a default of 600 seconds and a
  maximum of 7200 seconds (120 minutes)
- reports the `send`/`assign-*`/`report-request` TUI input-readiness gate:
  default 15 seconds, 0.5 second polling, visible input prompt required,
  fail-closed without paste via retryable `agent_input_not_ready`
- reports whether the current CLI/MCP owner identity is stable across
  invocations without returning the identity itself

`skills`
- scans each Agentin home for `SKILL.md` files in `skills/`, `plugins/cache/`,
  and `.tmp/plugins/`
- ignores symlinked skill roots and symlinked `SKILL.md` files instead of
  following them
- returns counts, roots, system-skill names, and bounded plugin/name pages
- reports `plugin_count`, `plugins_offset`, `plugins_limit`, and
  `plugins_truncated` instead of dumping every plugin name when many are
  installed
- supports deliberate enumeration through `plugins_offset`/`plugins_limit` and,
  with `include_names`, `names_offset`/`limit`
- returns no skill file contents and no Agentin terminal output

`capabilities`
- returns the model policy, total skill count, system skill names, and a bounded
  first plugin page
- reports `plugin_count`, `plugin_page_count`, `plugins_limit`, and
  `plugins_truncated` instead of dumping every plugin name when many are
  installed

## App Bridge

The plugin includes `.app.json` and declares it through
`.codex-plugin/plugin.json`:

```json
{
  "apps": {
    "codex-master": {
      "id": "connector_26697a678b7ec999dc005131eb5c087c"
    }
  }
}
```

This is the local App Bridge identity for the `codex-master` plugin. It keeps
the existing data-sparse MCP tool surface and lets Codex associate the plugin
with a stable connector ID. The ID is intentionally not a secret.

For a ChatGPT Developer Mode connector, ChatGPT still has to create or refresh
the connector against a reachable public HTTPS `/mcp` endpoint. The current
Masterjet MCP runs as a local stdio MCP for Codex, so `.app.json` organizes the
plugin-side bridge identity; it does not publish the repo to a Marketplace or
turn the local stdio command into a hosted HTTP connector by itself.

Check the bridge state without local paths:

```sh
python3 -m codex_master.server app-bridge-status
```

## Steering Skills

Skills are not invoked as separate MCP functions. They are instruction bundles
that a Codex Agentin uses when the task names the skill or clearly matches its
domain.

```sh
python3 -m codex_master.server skills all --agents-limit 30
python3 -m codex_master.server send a "Nutze codex-security:security-scan. Pruefe src/codex_master/server.py nur lesend und berichte knapp."
python3 -m codex_master.server send b "Nutze github:gh-fix-ci. Pruefe die CI-Konfiguration nur lesend und berichte knapp."
python3 -m codex_master.server tail a --source pane --lines 20 --chars 2000
```

For safer delegation, prefer `assign-readonly`, `assign-live-data`, and
`assign-write` over free-form `send`:

```sh
python3 -m codex_master.server assign-readonly a \
  --skill codex-security:security-scan \
  --scope src/codex_master/server.py \
  --task "Pruefe nur lesend und berichte knapp."

python3 -m codex_master.server assign-live-data a \
  --task "Wie ist das Wetter gerade in Berlin?" \
  --live-data-topic "Wetter Berlin heute"

python3 -m codex_master.server assign-write b \
  --skill github:gh-fix-ci \
  --scope .github/workflows \
  --write-path .github/workflows/ci.yml \
  --task "Haerte nur die CI-Datei und berichte Root Cause, Aenderung, Tests, Risiken."
```

`assign` validates named skills by inventory, refuses write paths for
Exploriererinnen, and requires explicit write paths for Arbeitsbienen. It sends
the generated prompt through tmux but does not return the prompt or the Agentin
response.

Use `assign-live-data` for weather, news, prices, schedules, or any other
current-data task. It is read-only, uses the same auth and lease guards as other
assignments, and injects an explicit requirement to use current search sources
or report a tooling/access limit instead of guessing. The concrete live-data
topic is sent only to the Agentin prompt; public responses and assignment audit
records keep the topic and response content out of returned data.

`assign-write` also gates write paths through `agent_scope_check`; a write path
outside the declared scope is rejected before anything is sent to an Agentin.
Worktree creation refuses existing targets, including broken symlinks, and
requires every parent directory in the target path to be a real directory.
Worktree creation and status are repo-scoped: relative escapes and absolute
targets outside the repo are rejected before running `git`, and create responses
return at most a repo-relative path, never an absolute local path. Worktree
status also refuses symlinks and non-directory targets before running
`git status`.
Assignment and send inputs are bounded before tmux interaction: free sends and
start prompts are capped at 12,000 characters, assignment tasks at 4,000
characters, names at 80 characters, skill refs at 300 characters, path-like
fields at 1,000 characters, and assignment lists at 50 items. MCP boolean and
integer arguments are type-checked; stringified values are rejected instead of
being coerced. Incoming MCP frames are capped at 1 MiB before JSON parsing.
Tool and RPC error texts are ANSI-stripped, redacted, and length-bounded before
they are returned. `tools/call` validates tool names, object-shaped params and
arguments, unknown argument names, required fields, value types, enums, and
declared bounds before dispatch. Local CLI tool commands pass through the same
schema validation, with omitted optional arguments removed before validation.
Multiline `send` and `assign-*` payloads are wrapped with bracketed-paste
markers before tmux paste so Codex TUI treats the template as one prompt instead
of separate submitted lines.

Before mutating one Agentin, `start`, `assign-*`, `send`, `report-request`,
`interrupt`, and `stop` check or renew a per-Agentin lease. A second MCP client
gets a structured retryable error instead of writing into the same tmux session.
Fresh `start` leases are released again after a successful launch; this keeps
the local CLI usable across separate invocations while still serializing the
start operation itself. Existing claims held by the same connected client are
preserved.
Use `claim` when a Codex-CLI instance should wait for a busy Agentin; it retries
forever by default with bounded polling intervals. Use `claim --no-wait` for a
single immediate attempt, or `claim --wait-seconds ...` for an explicit finite
limit. Explicit `claim` recovers a stopped foreign lease only after the stopped
grace period, default 120 seconds, when the Agentin is not running and no
process is using that managed Agentin home. Use `claim --no-recover-stopped`
when an operator wants strict TTL-only behavior. Lease state is metadata only
and does not return the client identity, prompt text, Agentin output, or local
state path.

Raw logs are local debug artifacts, not normal API data. The tmux pipe writes
through a bounded local writer, `doctor` reports the configured raw-log policy,
and `tail --source log` refuses metadata paths outside the managed raw-log state.
Managed raw logs must be regular files; symlinks are not followed and are pruned
from raw-log directories. The hidden raw-log writer rejects `--max-bytes` values
outside the active raw-log policy before touching state or paths. Use `tail`
only when an explicit, capped, ANSI-stripped, redacted excerpt is needed. Failed
starts remove their prepared raw-log file before returning an error.

Model policy is resolved once through the central class/lifecycle/model/effort
resolver documented above. Start and assignment responses expose the effective
selection, fallback state, and reason codes; assignment audit metadata records
the effective model without storing prompts or responses.

Agentinnen may start their own native Subagentinnen only when the assignment
uses `--allow-subagents`. Without that flag, the generated assignment explicitly
forbids nested delegation. Even with the flag, nested Agentinnen stay inside the
assigned scope and write paths; they do not use `codex-master-mcp` and they do
not commit, push, or release.

Do not start a managed Agentin manually with the same `CODEX_HOME` while the
Masterjet is responsible for her. `start` refuses to launch an Agentin when her
home is already used by an external Codex process, and `doctor` reports such
home conflicts before they become tmux or lock contention. `start` also refuses
an already-running Masterjet session if a second external process is using the
same home. `install` refuses to register `codex-master-mcp` from a managed
Agentinnen home so the Masterjet tools stay in the Teamleiterin/main instance.

Assignments are appended to `~/.local/state/codex-master-mcp/assignments.jsonl`
as metadata only: assignment id, Agentin, role, selected model, skill match
status, scope, write paths, counts, and flags. Prompt text and Agentin responses
are not stored or returned, and assignment query responses do not return the
local audit file path. The audit file is retained as a bounded local JSONL ledger:
the newest 500 valid metadata records are kept, invalid legacy lines are dropped
during pruning, and the file is rewritten with `0600` permissions. Private state
appends refuse symlink paths, Agentin metadata is written atomically, and
nonce-suffixed temporary replace files are created with no-follow exclusive semantics. Managed
state directories and their parent chains must be real directories, not symlinks
or regular files.
External process calls are timeout-bounded and return structured timeout
failures instead of blocking the MCP server indefinitely.
`agent_doctor` also reports the active `CODEX_HOME` context without returning
the path, and checks that `codex-master-mcp` has a `startup_timeout_sec` of at
least 120 seconds in the active Codex MCP configuration.

Use `tail` only when an explicit, capped excerpt is needed. Normal status and
send operations do not return Agentin output. `tail` refuses to read pane or log
output while the selected Agentin has an active lease held by another MCP
client; claim the Agentin first or wait for the lease to expire.

## Plugin

This repo is also a local Codex plugin:

- `.codex-plugin/plugin.json`: plugin metadata and Codex UI information
- `.mcp.json`: starts `codex-master-mcp` from this repo without package install
  and declares `startup_timeout_sec = 120`
- `skills/codex-master-fleet/SKILL.md`: Teamleiterin skill for the Masterjet

The plugin is intended for the main/Teamleiterin Codex instance. Managed
Agentinnen should keep their separate worker skill and should not receive
Masterjet MCP tools.

A Marketplace entry is optional. The repo contains the plugin artifacts, and the
existing `codex-master-mcp` registration can run the MCP server directly. Add a
personal/local Marketplace entry only if you want Codex's plugin UI to discover
and install it as a plugin.

## Checks

```sh
git diff --check
PYTHONPATH=src python3 -m compileall -q src tests
PYTHONPATH=src python3 -m unittest discover -s tests -v
./bin/codex-master-mcp tools
```

`./bin/codex-master-mcp commit-ready-check` runs the local release gate for
`git diff --check`, `compileall`, and the unit tests.

GitHub Actions uses `.github/workflows/ci.yml` to run the same source and unit
test gates, plus plugin/App/MCP manifest validation, committed-whitespace
checks for the pushed or pull-request commit range, a CLI wrapper smoke check,
full-SHA pinning checks for external workflow actions, and a temporary
agent-pool installer smoke for `validate`, `install`, `status`, and
`destroy_pool`.
