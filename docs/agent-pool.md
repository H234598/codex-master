# Agentinnen Pool

`codex-master` can install a sleeping Codex Agentinnen pool from a JSON spec.
The installer creates per-Agentin `CODEX_HOME` directories, a regular executable
`codex` wrapper, a minimal `config.toml`, private runtime directories, and a
pool marker. It does not start Agentinnen.

The pool spec is a map, not a secret store. `codex-agent-pool.json` describes
which Agentinnen exist, where the pool root is, which source homes are expected
to be authenticated, and which selectors should resolve to which homes. The
actual authentication material remains in each Agentin home as `auth.json`.

Default layout:

```text
~/.codex-agents/
  a1/
    auth.json        # real auth file, if this source home is authenticated
    codex            # regular executable wrapper, not a symlink
    config.toml
  a2/
    codex
    config.toml
  b1/
    auth.json
  c1/
    codex
```

The default spec describes `a1..a100`, `b1..b100`, and `c1..c100`. `a1` and
`b1` are authenticated source homes; the C series is intentionally unauthenticated
until another account is available.

Selectors are case-insensitive. `A1`, `a1`, `A-Series`, and `a-series` resolve
to the same Agentinnen. Numeric selectors are single-Agentin shortcuts driven
by a small policy. The default policy alternates A and B:

```text
1 = a1
2 = b1
3 = a2
4 = b2
```

Switch to an A/B/C rotation when C homes should participate in ordinal
selection:

```sh
./bin/codex-master-mcp selector-policy --series a,b,c
./bin/codex-master-mcp selector-preview --series a,b,c --limit 6
```

The persisted policy lives in private MCP state and tool responses return
`policy_file: not_returned`. For a one-process override, set
`CODEX_MASTER_AGENT_SELECTOR_SERIES=a,b,c`.

Teamleiterinnen may spawn fremde Bienen directly through `agent_start`,
`agent_claim`, and structured assignments. The safety model is the per-Agentin
lease plus auth and scope gates, not an indirect handoff through native
Subagentinnen.

Default install:

```sh
./bin/codex-master-mcp pool validate --spec codex-agent-pool.json
./bin/codex-master-mcp pool install --spec codex-agent-pool.json
./bin/codex-master-mcp pool status --spec codex-agent-pool.json
```

Install into a custom target directory and point wrappers at a non-standard
Codex CLI binary:

```sh
./bin/codex-master-mcp pool install \
  --spec codex-agent-pool.json \
  --target-dir "$HOME/.codex-agents" \
  --codex-bin /usr/local/bin/codex
```

Shortcut wrapper:

```sh
./scripts/install-agent-pool --spec codex-agent-pool.json --target-dir "$HOME/.codex-agents"
```

## Commands

`pool validate` reads the spec, expands supported environment defaults such as
`${HOME}` and `${CODEX_AGENT_BIN:-/usr/local/bin/codex}`, and returns only
counts and state markers. It does not echo concrete series, alias, or
authenticated Agentin names. The resolved `codex_bin` must be non-empty,
bounded, free of control characters, and usable before it is written into
generated wrappers: path-like values must resolve to an executable file, while
plain command names must resolve on `PATH`. Generated wrappers execute the
selected binary with `exec --`, so an unusual but valid command name is treated
as command data rather than as an `exec` option.

`pool install` is idempotent. It creates missing Agentin homes, regular
executable wrappers, minimal configs, runtime directories, and an installed pool
marker. It does not start Agentinnen and does not copy auth by default.

Running Agentinnen are driven through tmux. The Masterjet pastes text into the
Codex TUI and submits with `S-Enter`; plain `Enter` can remain in the composer
for multi-line or wrapped prompts in current Codex CLI builds.
Before pasting, `send`, `assign-*`, and `report-request` wait briefly for a
visible Codex TUI input prompt marker in the current visible pane tail. If the
TUI is still starting, only shows starter text, or only startup warnings are
visible, the mutation fails closed with retryable `agent_input_not_ready` and
`paste_attempted: false` instead of silently losing the prompt. `timeout-policy`
reports this readiness gate with its default 15 second timeout and 0.5 second
poll interval.

For weather, news, prices, schedules, and other current-data tasks, prefer
`assign-live-data` over raw `send`. It is a read-only Exploriererin assignment
that tells the Agentin to use current search sources or report a tooling/access
limit instead of guessing. Public tool responses and assignment audit records
still omit prompt text and Agentin output.

`pool status` counts installed homes, wrappers, configs, auth files, the
installed pool marker, series count, and shared asset symlinks. It also reports
data-sparse shared-asset integrity counters for expected, valid, missing, and
invalid non-template links plus required template sources. Its top-level `ok`
requires all expected homes, regular wrappers, regular configs, a regular
installed pool marker, no missing or invalid shared-asset links, and no missing
template sources that are required by other Agentinnen. It returns
`pool_root: not_returned`, not local paths, and does not echo concrete series
names.

`pool copy_auth` copies one source `auth.json` to many installed Agentinnen.
Without `--yes` it is a dry-run and only reports copy counts.

```sh
./bin/codex-master-mcp pool copy_auth --spec codex-agent-pool.json --from-agent a1 --to a-series
./bin/codex-master-mcp pool copy_auth --spec codex-agent-pool.json --from-agent a1 --to a-series --yes
```

`pool destroy_pool` removes only the Agentin entries described by the spec. It
requires `--yes` and a regular installed pool marker unless `--force` is passed.
Directory removal fails closed if the Python runtime cannot provide
symlink-attack-resistant `rmtree` semantics.

## Auth Rules

Auth is intentionally not copied during normal install. To inspect a mass-copy
operation first, omit `--yes`; to apply it, repeat the same command with
`--yes`.

MCP working mutations require each selected Agentin to have a regular local
`auth.json` by default. This protects Teamleiterinnen from accidentally
starting or assigning unauthenticated sleeping homes such as `c2`. The guarded
tools are `agent_start`, `agent_claim`, `agent_send`, `agent_assign`,
`agent_interrupt`, `agent_assign_readonly`, `agent_assign_live_data`,
`agent_assign_write`, and `agent_report_request`. Read-only diagnostics, pool
inspection, stop, release, and watchdog cleanup remain usable. Use
`--allow-unauthenticated` only for explicit login/bootstrap flows.

`copy_auth`:

- reads only `<pool-root>/<from-agent>/auth.json`
- requires the source Agentin to be part of the pool spec
- requires the source Agentin home to be a real directory, not a symlink
- resolves the target selector through the same spec
- skips the source Agentin if the target selector includes it
- skips missing target homes
- skips existing target `auth.json` unless `--overwrite` is set
- writes target auth files as private regular files
- never returns auth file content
- never echoes the source Agentin id or requested target selector
- never returns the pool root path

Do not symlink or hardlink `auth.json` as the normal mode. Auth files are small,
and shared auth identity has worse failure modes than the saved bytes. A symlink
breaks the no-follow trust boundary. A hardlink keeps one shared inode, so
rotation or corruption from one Agentin affects every linked Agentin.

See `docs/auth-copy.md` for examples and the full safety model.

## Destruction

```sh
./bin/codex-master-mcp pool destroy_pool --spec codex-agent-pool.json --yes
```

For a custom pool root:

```sh
./bin/codex-master-mcp pool destroy_pool \
  --spec codex-agent-pool.json \
  --target-dir "$HOME/.codex-agents" \
  --yes
```
