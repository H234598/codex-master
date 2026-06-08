# codex-master

Local MCP wrapper for controlling a sleeping/scalable Codex Agentinnen pool:

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

The wrapper starts instances through their per-home `codex` launcher files
with the default model `gpt-5.4-mini` and:

```sh
--model gpt-5.4-mini -c 'model="gpt-5.4-mini"' -c 'model_reasoning_effort="medium"' --yolo -s danger-full-access --search
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
Text is pasted into the Codex TUI through tmux and submitted with `S-Enter`.
Plain `Enter` can leave multi-line or wrapped prompts sitting in the composer
instead of starting the model response in current Codex CLI builds.
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
Working mutations require a regular per-Agentin `auth.json` by default:
`agent_start`, `agent_claim`, `agent_send`, `agent_assign`,
`agent_assign_readonly`, `agent_assign_live_data`, `agent_assign_write`, and
`agent_report_request` fail closed when auth is missing, symlinked, not a
regular file, unreadable, or too large. Status/skills/capabilities/lease/pool/
stop/release remain available for diagnosis and cleanup. Use
`--allow-unauthenticated` only for explicit login/bootstrap flows.
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

## Tools

- `agent_start`: start selected Agentinnen (`a1`, `b1`, `c1`, series selectors,
  `both`, or `all`)
- `agent_status`: structured status, response state, and limit classification
  without raw output
- `agent_lease_status`: data-sparse lease state for selected Agentinnen
- `agent_claim`: claim or renew one Agentin, retrying forever by default when
  she is busy; explicit claims may recover stopped orphan leases after grace
- `agent_release`: release this MCP client's Agentin claim; force only after
  checking status
- `agent_wait`: wait for activity/stop/limit metadata without raw output,
  defaulting to 120 seconds and capped at 10 minutes per call
- `fleet_watchdog`: request a report from idle Agentinnen, wait a grace window,
  then optionally interrupt, stop, or release without raw output
- `agent_send`: send text to one running Agentin
- `agent_interrupt`: send Ctrl-C to one running Agentin
- `agent_stop`: stop selected Agentinnen
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
- `agent_selector_policy`: show or set the ordinal selector policy, for example
  `a,b` or `a,b,c`
- `agent_selector_preview`: preview numeric selector mapping without mutating
  state
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
  startup, Agentin claim retry, Agentin wait, watchdog supervision, and
  hidden CLI lease identity source
- `agent_pool_validate`: validate a machine-readable Agentinnen pool spec
- `agent_pool_install`: install or refresh sleeping Agentinnen homes from a spec
- `agent_pool_status`: inspect data-sparse pool installation counts
- `agent_pool_copy_auth`: explicitly copy one source `auth.json` to many
  installed Agentinnen, dry-run by default
- `agent_pool_destroy_pool`: guarded removal of installed Agentinnen homes
- `agent_doctor`: structured diagnostics without raw output

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

```sh
cd /home/teladi/codex-master
python3 -m codex_master.server install          # create ~/.local/bin/codex-master-mcp + codex mcp add
python3 -m codex_master.server doctor          # smoke check (codex, tmux, state path, JSON result)
python3 -m codex_master.server uninstall       # remove mcp registration and local symlink

python3 -m codex_master.server start both --cwd /home/teladi/codex-master
python3 -m codex_master.server status
python3 -m codex_master.server selector-policy
python3 -m codex_master.server selector-policy --series a,b,c
python3 -m codex_master.server selector-preview --limit 6
python3 -m codex_master.server lease-status all
python3 -m codex_master.server claim b --forever --poll-interval-seconds 30
python3 -m codex_master.server claim b --no-wait
python3 -m codex_master.server claim b --no-recover-stopped
python3 -m codex_master.server wait a --timeout-seconds 120 --poll-interval-seconds 30
python3 -m codex_master.server watchdog all --idle-seconds 60 --poll-interval-seconds 15 --report-grace-seconds 15 --action stop --manage-unclaimed --quiet
python3 -m codex_master.server capabilities all
python3 -m codex_master.server skills all
python3 -m codex_master.server skills a --include-names --limit 20 --names-offset 20 --plugins-offset 20 --plugins-limit 20
python3 -m codex_master.server skill-match all codex-security:security-scan
python3 -m codex_master.server scope-check --scope src/codex_master --write-path src/codex_master/server.py
python3 -m codex_master.server assign-readonly a --skill codex-security:security-scan --scope src/codex_master/server.py --task "Pruefe nur lesend und berichte knapp."
python3 -m codex_master.server assign-live-data a --task "Wie ist das Wetter gerade in Berlin?" --live-data-topic "Wetter Berlin heute"
python3 -m codex_master.server assign-write b --scope .github/workflows --write-path .github/workflows/ci.yml --task "Haerte nur die CI-Datei."
python3 -m codex_master.server assignments all --limit 20
python3 -m codex_master.server last-assignment a
python3 -m codex_master.server integration-status
python3 -m codex_master.server commit-ready-check
python3 -m codex_master.server app-bridge-status
python3 -m codex_master.server plugin-status
python3 -m codex_master.server namespace-status
python3 -m codex_master.server release-status
python3 -m codex_master.server watchdog-status
python3 -m codex_master.server timeout-policy
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
`schemas/codex-agent-pool.schema.json`. The default spec describes the current
300-Agentinnen pool: `a1..a100`, `b1..b100`, and `c1..c100`, with `a1` and
`b1` marked as the authenticated source homes and the C series intentionally
unauthenticated.
Pool spec reads accept only regular UTF-8 JSON files, reject symlinked or
oversized spec files, and keep spec paths out of public error responses.
Pool install also keeps generated `codex` wrappers and `config.toml` files as
per-Agentin regular files, replacing symlinked entries without touching their
targets, validates runtime directories as real directories, and writes a
regular installed-pool marker. Pool status reports `ok` only when the marker,
all expected homes, wrappers, configs, and required shared-asset links are
present and valid. Shared-asset diagnostics are counts only; local link targets
and pool paths are not returned.

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
Agentin when she is part of the target selector, and never returns auth content,
the source Agentin id, or the requested target selector.

Do not use symlinks or hardlinks for `auth.json` in the normal pool model.
Auth files are small; copies keep each Agentin isolated. Symlinks cross the
no-follow trust boundary, and hardlinks share one inode across multiple
Agentinnen.

See `docs/agent-pool.md` for the full command set and `docs/auth-copy.md` for
the auth-copy safety model.

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
  empty `CapabilityBoundingSet`, private keyring/tmp/devices, kernel and clock
  protections, read-only system hierarchy, explicit write access only to the
  managed state and user runtime directories, no IP sockets, no namespaces,
  `NoNewPrivileges`, `MemoryDenyWriteExecute`, native syscall architecture,
  and `UMask=0077`; it intentionally keeps normal user home read access because
  the watchdog needs Codex config, tmux IPC, and managed state files

`watchdog-status`
- reports whether the systemd timer is active and whether the last service run
  succeeded, without returning raw `systemctl` output
- checks that the installed watchdog service and timer match the repo copies
  and that the service still contains the required hardening directives and
  watchdog flags
- parses only the aggregate `systemd-analyze security` exposure score and
  level; raw analyzer output and local unit paths are not returned

`timeout-policy`
- reports that `agent_claim` retries forever by default for busy fremde Bienen,
  while finite claim waits are still accepted without a 600 second cap
- reports that claim polling defaults to 30 seconds and is capped at 900 seconds
- reports stopped foreign lease recovery defaults for explicit claims: only
  stopped Agentinnen, no managed-home process, and sufficient idle evidence
- keeps `agent_wait` separate as a bounded activity wait: default 120 seconds,
  maximum 600 seconds
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
python3 -m codex_master.server skills all
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

Model policy: managed Agentinnen run on `gpt-5.4-mini` by default. Read-only
Exploriererin assignments keep that model. Arbeitsbiene write assignments are
marked for `gpt-5.3-codex-spark` in the structured assignment and audit metadata.

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
PYTHONPATH=src python3 -m compileall -q src tests
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

The same checks run in GitHub Actions via `.github/workflows/ci.yml`.
