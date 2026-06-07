---
name: codex-master-fleet
description: Use when managing the local codex-master-mcp Masterjet, Codex Agentinnen pool, Bienen, Arbeitsbienen, Exploriererinnen, fleet variables, plugin status, or persistent feminine agent delegation rules.
metadata:
  short-description: Manage codex-master-mcp and the local Agentinnen fleet
---

# Codex Master Fleet

Use this skill in the Teamleiterin/main Codex instance when the user refers to
the Masterjet, `codex-master`, `codex-master-mcp`, the Agentinnen pool, Bienen,
Arbeitsbienen, Exploriererinnen, fleet rules, plugin status, telint imports, or
the persisted delegation templates.

This skill is for the controlling instance. Do not install it into managed
Agentinnen unless the intent is to make that instance a Teamleiterin.

`codex-master-mcp` Agentinnen are fremde Bienen: they are controlled through an
MCP/plugin boundary. Eigene Bienen are native Subagentinnen spawned without MCP;
manage those with the `subagent-fleet` / `multi_agent_v1` workflow instead.
Fremde-Eigene Bienen are fremde Bienen whose lease is currently held by the
Teamleiterin/current controlling instance; coordinate them as leased external
Bienen, not as native Subagentinnen.
For eigene Bienen, the requested model may be selected through a hidden
`multi_agent_v1.spawn_agent` `model` parameter even when the visible schema does
not show it; test the user's model IDs instead of assuming they are unavailable.

## Model Policy

- Managed Agentinnen run on `gpt-5.4-mini` by default with medium
  reasoning effort.
- Exploriererin/read-only assignments keep `gpt-5.4-mini`.
- Arbeitsbiene write assignments are marked for `gpt-5.3-codex-spark` with low
  reasoning effort.
- If a running Codex TUI cannot switch model mid-session, the assignment still
  carries `Modell: gpt-5.3-codex-spark` as the required escalation signal.

## Fleet Policy

- Use feminine wording: `Agentin`, `Biene`, `Arbeitsbiene`,
  `Exploriererin`, `Teamleiterin`.
- If masculine agent wording appears, briefly note the mismatch and continue
  with the feminine term.
- Give Agentinnen modern female names unless the user requests a fixed name.
- The main instance is the Teamleiterin. It may inspect and integrate, but
  should mainly coordinate, test, commit, push, and release.
- Default eigene-Bienen fleet size is 2-3 Bienen. Maximum is 6, only for
  independent tasks. In addition, use 1-2 fremde Bienen through MCP/plugin
  control surfaces when useful and safe.
- Exploriererinnen read, analyze, and report concise context packages only.
- Arbeitsbienen may write only in assigned files or isolated workspaces.
- Before assigning writes, inspect `git status --short` and avoid overlapping
  write scopes.
- Security is more important than performance; still keep performance in mind.
- Version all coding steps. Commit after 10 successful fixes, push after 10
  commits, release after 10 pushes. Push/release only with green tests and no
  known critical findings.
- Managed Agentinnen may start native Subagentinnen only when the assignment explicitly
  allows it. Nested Subagentinnen must stay inside the assigned scope and write
  paths. They must not use `codex-master-mcp` to control the fleet.
- Use codex-master-mcp for fremde Bienen and native `multi_agent_v1`
  Subagentinnen for eigene Bienen. Keep their ownership, scopes, and reporting
  separate so the Teamleiterin can integrate safely.
- Do not manually start a managed Agentin with the same `CODEX_HOME` while the
  Masterjet manages them. Use `doctor` if a terminal looks stuck; `start`
  blocks when an Agentin home is already used externally, including when a
  Masterjet tmux session already exists. Agentin runners must be regular
  executable files, not symlinks.
- A stopped Agentin is a normal informational `doctor` session state, not a
  failed health check.

## MCP Visibility

In `/mcp`, the main Codex instance should show `codex-master-mcp`. Managed
Agentinnen intentionally should not show the Masterjet MCP tools. If a standard
instance says that Master MCP Tools are none, then either that instance is not
the Teamleiterin, or `codex-master-mcp` is not installed/configured there.

## Agentinnen Pool

- Homes live under `~/.codex-agents/<id>`.
- Concrete ids are `a1..a100`, `b1..b100`, and `c1..c100`.
- Legacy aliases `a` and `b` resolve to `a1` and `b1`; `both` resolves to
  `a1,b1`.
- Series selectors are `a-series`, `b-series`, `c-series`; `all` covers all
  300 Agentinnen.
- `a1` and `b1` preserve the authenticated original homes. Additional homes are
  sleeping/slim by default and must not receive copied auth material without an
  explicit user instruction.
- Prefer symlinks for read-mostly large content such as skills, plugins, and
  model caches. Keep runtime state, wrappers, config, tmux sessions, leases, and
  metadata per Agentin.

## Masterjet Control

Prefer structured tools over raw `send`:

```sh
cd /home/teladi/codex-master
./bin/codex-master-mcp doctor
./bin/codex-master-mcp status
./bin/codex-master-mcp lease-status all
./bin/codex-master-mcp claim b1 --forever --poll-interval-seconds 30
./bin/codex-master-mcp claim b1 --no-wait
./bin/codex-master-mcp claim b1 --no-recover-stopped
./bin/codex-master-mcp wait a1 --timeout-seconds 120 --poll-interval-seconds 30
./bin/codex-master-mcp watchdog all --idle-seconds 60 --poll-interval-seconds 15 --report-grace-seconds 15 --action stop --manage-unclaimed --quiet
./bin/codex-master-mcp start both --cwd /home/teladi/codex-master
./bin/codex-master-mcp capabilities all
./bin/codex-master-mcp skills all
./bin/codex-master-mcp skills a1 --include-names --limit 20 --names-offset 20 --plugins-offset 20 --plugins-limit 20
./bin/codex-master-mcp skill-match all codex-security:security-scan
./bin/codex-master-mcp scope-check --scope src --write-path src/codex_master/server.py
./bin/codex-master-mcp assign-readonly a1 --skill codex-security:security-scan --scope src/codex_master/server.py --task "Pruefe nur lesend und berichte knapp."
./bin/codex-master-mcp assign-live-data a1 --task "Wie ist das Wetter gerade in Berlin?" --live-data-topic "Wetter Berlin heute"
./bin/codex-master-mcp assign-write b1 --skill github:gh-fix-ci --scope .github/workflows --write-path .github/workflows/ci.yml --task "Haerte nur die CI-Datei."
./bin/codex-master-mcp assignments all --limit 20
./bin/codex-master-mcp last-assignment a1
./bin/codex-master-mcp report-request a1
./bin/codex-master-mcp integration-status
./bin/codex-master-mcp commit-ready-check
./bin/codex-master-mcp app-bridge-status
./bin/codex-master-mcp plugin-status
./bin/codex-master-mcp namespace-status
./bin/codex-master-mcp release-status
./bin/codex-master-mcp watchdog-status
./bin/codex-master-mcp timeout-policy
./bin/codex-master-mcp release b1
```

Data minimization:

- `status`, `wait`, `watchdog`, `start`, `send`, `assign-*`, `doctor`,
  `skills`, `capabilities`, `app-bridge-status`, `plugin-status`,
  `namespace-status`, `release-status`, `watchdog-status`, and
  `timeout-policy` do not return Agentin terminal output.
- For weather, news, prices, schedules, and other current-data tasks, prefer
  `assign-live-data` over raw `send`. It is a read-only assignment that tells
  the Agentin to use current search sources or report a tooling/access limit
  instead of guessing. Public responses and assignment audit records still omit
  prompt text and Agentin output.
- `send` and `assign-*` wait briefly for a visible Codex TUI input prompt before
  pasting. If an Agentin is still in startup warnings, the mutation should fail
  closed instead of silently losing the prompt.
- `watchdog` is data-sparse and two-phased. When an Agentin is idle, it first
  requests a concise report and stores only a metadata marker. It waits the
  report grace period, default 15 seconds, before `interrupt`, `stop`, or
  `release`. The default watchdog idle threshold is 60 seconds; the systemd
  timer poll interval is 15 seconds. The installed systemd supervisor uses
  `--action stop`, so unused Agentinnen are put back to sleep after the report
  grace period. By default it only mutates Agentinnen held by the current
  server. The systemd supervisor may additionally manage unclaimed or expired
  leases via `--manage-unclaimed --quiet`; it must still skip active leases held
  by other clients.
- The watchdog user service should keep conservative systemd hardening:
  empty `CapabilityBoundingSet`, private keyring/tmp/devices, kernel and clock
  protections, `ProtectSystem=strict`, `ReadWritePaths` for managed state plus
  user runtime, no IP sockets, no namespaces, `NoNewPrivileges`,
  `MemoryDenyWriteExecute`, native syscall architecture, and `UMask=0077`. Do
  not add `ProtectHome` or similar home-blocking settings unless the service is
  redesigned around explicit read/write paths, because it needs Codex config,
  tmux IPC, and managed state.
- `watchdog-status` is diagnostic and data-sparse. It may return systemd timer
  and service health metadata, installed-unit match booleans, required
  hardening directive booleans, watchdog flag booleans, and the aggregate
  `systemd-analyze security` exposure score/level. It must not return local
  unit paths or raw `systemctl`/`systemd-analyze` output.
- `timeout-policy` is diagnostic and data-sparse. It must show that `claim`
  retries forever by default for busy fremde Bienen, that finite claim waits
  have no 600-second maximum, that the claim poll interval defaults to
  30 seconds and is capped at 900 seconds, that `wait` remains a bounded
  Agentin-activity wait capped at 10 minutes, that explicit `claim` can recover
  stopped foreign leases only after its grace period, and whether the hidden
  lease owner identity is stable across CLI invocations. The identity itself
  must not be returned.
- `status`, `doctor`, `skills`, `capabilities`, `app-bridge-status`,
  `plugin-status`, `namespace-status`, and integration metadata must not return
  local Agentin home, runner, repo, manifest, installed symlink, or
  working-directory paths. Use state/category fields such as `path_state`,
  `home_kind`, `cwd_state`, and target-state markers instead. Raw-log retention
  diagnostics may return counts and byte totals, but not managed raw-log
  directory paths.
- `namespace-status` is the local diagnostic for whether `codex-master-mcp` is
  registered, starts, and exposes its MCP `tools/list` to new clients.
  `tool_search` is not authoritative for the local stdio MCP namespace.
- `plugin-status` and `namespace-status` report whether the repo plugin
  manifest version is installed in the local plugin cache, without returning
  cache paths.
- `namespace-status.ok` must mean the MCP server, local plugin cache, active
  Codex client config, and active `CODEX_HOME` context are ready. Keep
  `mcp_server_ready`, `plugin_cache_ready`, `client_config_ready`, and
  `active_home_ready` separate so server startup can be distinguished from
  stale client/plugin state, mismatched config, or a managed Agentin home.
- `running_process_summary.namespace_visibility` must return only aggregate
  client-home categories. Use it to distinguish custom homes that need their
  own MCP config from managed Agentin homes that are expected not to expose
  Master MCP tools.
- `doctor` must report the active `CODEX_HOME` category and the
  `codex-master-mcp` `startup_timeout_sec` health without returning the active
  home path.
- `status` must classify known Codex TUI starter/placeholder context as
  metadata-only `tui_context` and must not return pane text.
- `status` may classify bounded pane/log text into metadata-only response and
  limit states, but it must not return the classified text. Daily, weekly,
  token, quota, and rate limits must keep default Agentinnen-model limits
  separate from Spark write-model limits, including separate session,
  assignment, and inferred-limit model metadata.
- `wait` may poll status for bounded time, defaulting to 120 seconds and
  currently capped at 10 minutes, and return activity/stop/limit metadata, but
  it must not return Agentin output. The default poll interval is 30 seconds;
  the maximum poll interval is 900 seconds.
- Mutating tools must use a per-Agentin lease so two Codex-CLI clients cannot
  silently send assignments or text into the same Agentin. Lease conflicts must
  be structured and retryable with `error_code`, `retryable`,
  `retry_after_seconds`, and remaining lease seconds, but without returning
  client identity, prompt text, Agentin output, or state paths. `claim` retries
  forever by default for busy fremde Bienen, may also accept explicit finite
  waits without a 600-second cap, and must sleep between retries without holding
  the Agentin lifecycle lock. Explicit `claim` may recover a foreign held lease
  only when the Agentin is not running, no process is using that managed
  Agentin home, and local idle evidence is at least the stopped-grace threshold
  old, default 120 seconds. This stopped-orphan recovery must not apply to
  implicit send/report/interrupt mutations and must never override a running
  foreign Agentin. Short-lived CLI invocations should derive a stable hidden
  owner from `CODEX_THREAD_ID` when available; use `CODEX_MASTER_MCP_INSTANCE_ID`
  only as an explicit override for controlled sessions.
- Fresh `start` leases are transient and must be released after a successful
  launch, so short-lived local CLI commands do not block the next command. A
  pre-existing same-client claim must be preserved; use `claim` explicitly when
  a connected Codex-CLI instance should reserve an Agentin after startup.
- `capabilities` returns a bounded first plugin page plus counts/truncation
  flags, not a complete broad plugin inventory.
- `skills` returns bounded plugin/name pages plus total counts, offsets, limits,
  and truncation flags so callers can deliberately enumerate more pages without
  broad dumping. Symlinked skill roots and symlinked `SKILL.md` files are
  ignored instead of being followed.
- `assignments` and `last-assignment` return only assignment metadata. They
  must not return prompt text, Agentin responses, local audit file paths, or
  absolute local paths from historical `scope`/`write_paths` metadata.
- Assignment audit retention is bounded to the newest 500 valid metadata
  records in a local `0600` JSONL file. Assignment-log reads require regular
  files, are capped, and use generic errors. Private state appends refuse
  symlink paths, and private state file/directory errors must not expose local
  state paths. Agentin metadata is written atomically, and nonce-suffixed
  temporary replace files are created with no-follow exclusive semantics. Agentin metadata reads
  reject symlinked and oversized files, and metadata presence checks do not
  follow symlinks. Metadata read errors and legacy source markers must not
  expose local file paths. Managed state directories and their parent chains
  must be real directories, not symlinks or regular files.
- Raw logs are local debug artifacts. New raw logs are bounded to 5 MiB per
  file, managed raw-log directories retain at most 20 files by default, and
  log-tail metadata paths must stay inside managed raw-log state. Prepared
  raw-log files are created with no-follow exclusive semantics, and raw-log
  symlinks are not followed. The direct raw-log writer rejects `--max-bytes`
  values outside the active raw-log policy before touching state or paths,
  verifies real managed state directories before accepting log input, and
  symlinked legacy raw-log directories are ignored. Safe-tail log reads only
  regular raw-log files.
  Tmux control errors are redacted and bounded before they are returned or
  raised. Public tool responses expose raw-log presence without returning local
  raw-log paths. Failed starts must remove prepared raw-log files. External
  `tmux`, `git`, and `codex mcp` subprocess calls must be timeout-bounded.
  MCP registration checks must compare the exact `command:` field reported by
  `codex mcp get`, not substring-match broad command output.
  Agentin lifecycle operations that mutate or send into tmux sessions must be
  serialized per Agentin with private no-follow lock files. Failed
  `tmux new-session` attempts must not kill an already-existing session unless
  this process first created the session and is cleaning up a later start step.
- Assignment inputs are bounded before tmux interaction: sends/start prompts
  12,000 chars, tasks 4,000 chars, names 80 chars, skill refs 300 chars,
  path-like fields 1,000 chars, and assignment lists 50 items. MCP boolean and
  integer arguments are type-checked; stringified values are rejected instead of
  being coerced. Incoming MCP frames are capped at 1 MiB before JSON parsing.
  Tool and RPC error texts are ANSI-stripped, redacted, and length-bounded
  before they are returned. `tools/call` validates tool names, object-shaped
  params and arguments, unknown argument names, required fields, value types,
  enums, and declared bounds before dispatch. Local CLI tool commands must pass
  through the same schema validation, with omitted optional arguments removed
  before validation. Multiline sends and assignments must use bracketed paste
  before tmux paste so the Codex TUI receives one prompt, not separate submitted
  lines.
- Worktree creation must reject existing targets, including broken symlinks,
  and require every target parent directory to be a real directory. Worktree
  creation and status must stay repo-scoped: relative escapes and absolute
  targets outside the repo are rejected before running `git`, and create
  responses return at most repo-relative paths, never absolute local paths.
- Worktree status must reject symlinks and non-directory targets before running
  `git status`, and public worktree status responses must not return local
  worktree paths or absolute paths in git worktree excerpts.
- Install and uninstall symlink operations must require the install-path parent
  chain to be real directories. Install, uninstall, and doctor must resolve
  install symlinks defensively: broken, looping, or unreadable symlinks are
  non-matching, and doctor reports an unreadable target marker instead of
  crashing. Install must persist `startup_timeout_sec = 120` for the active MCP
  registration and refuse Master MCP registration from a managed Agentinnen
  `CODEX_HOME`. Install must sync the personal `codex-master` plugin cache from
  a runtime allowlist and exclude `.git`, tests, bytecode, test caches, hidden
  files, editor swap files, and backup/patch leftovers. Plugin-cache sync must
  copy regular files through no-follow file descriptors, verify source identity
  after opening, reject hardlinked source files, and retain only the current
  plus recent valid cached versions without pruning invalid, symlinked, or
  pre-existing temp cache entries it did not create. Install
  symlink creation/replacement must use an atomic same-directory temporary
  symlink rename bound to a verified parent directory fd. Uninstall symlink
  removal must also be bound to the verified parent directory fd so parent-swap
  races cannot redirect the unlink. Public install responses must not return
  plugin-cache paths.
  Registering installs must data-sparse self-test both the repo
  wrapper and the installed command path before registration. Public install
  responses must not return the install path or repo-wrapper target path; return
  state/kind fields instead. `doctor` must run the same data-sparse startup
  self-test, tolerate unavailable commands without raw error output, and warn
  without returning changed file names when the installed MCP points at a dirty
  repo worktree.
- The App Bridge identity lives in `.app.json`, declared from
  `.codex-plugin/plugin.json` via `apps: "./.app.json"`. `app-bridge-status`
  may return the connector ID because it is not secret, but it must not return
  local manifest paths or raw file contents. ChatGPT Developer Mode connector
  creation/refresh is still an external ChatGPT settings action against a
  reachable HTTPS `/mcp` endpoint; the local stdio MCP is not published by the
  App Bridge manifest alone.
- `release-status` must remain diagnostic and data-sparse: it may return
  public version/tag names, release drift counts, and blocker/warning codes, but
  not local repo paths or raw `git`/`gh` command output. It should make stale
  GitHub releases and local tags without GitHub releases visible without
  forcing a release.
- Use `tail` only for an explicit capped, ANSI-stripped, redacted excerpt.
- Do not read raw tmux logs directly unless the user explicitly requests it and
  the privacy impact is acceptable.

## Delegation Templates

Exploriererin:

```text
[EXPLORER_BEE_TASK]
Name: {moderner weiblicher Name}
Rolle: Exploriererin
Modell: gpt-5.4-mini
Scope: {Dateien/Ordner/Webthema}
Darf schreiben: nein
Darf eigene Subagentinnen starten: {ja/nein, nur lesend im Scope}
Aufgabe: {konkrete Frage}
Rueckgabe: knappe Fakten, relevante Dateien/Zeilen, Empfehlung
```

Arbeitsbiene:

```text
[WORK_BEE_TASK]
Name: {moderner weiblicher Name}
Rolle: Arbeitsbiene
Modell: gpt-5.3-codex-spark
Scope: {Dateien/Ordner}
Darf schreiben: ja, nur {genaue Pfade}
Darf eigene Subagentinnen starten: {ja/nein, nur innerhalb Scope und Schreibpfaden}
Stabiler Kontext: {max. 8 Stichpunkte}
Aktuelle Aufgabe: {konkreter Fix}
Grenzen: {was nicht anfassen}
Rueckgabe: Root Cause, Aenderung, Tests, offene Risiken
```
