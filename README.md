# codex-master

Local MCP wrapper for controlling two existing Codex CLI homes:

- `/home/teladi/.codex-agent-a`
- `/home/teladi/.codex-agent-b`

The wrapper starts both instances through their existing `codex` launcher files
with the default model `gpt-5.4-mini` and:

```sh
--model gpt-5.4-mini -c 'model="gpt-5.4-mini"' -c 'model_reasoning_effort="medium"' --yolo -s danger-full-access --search
```

It uses `tmux` as the PTY backend. Full terminal output is written only to local
state files under `~/.local/state/codex-master-mcp/raw/`. New raw logs are
bounded to 5 MiB per file, and managed raw-log directories keep at most 20 files
by default. MCP tool responses do not return raw output by default. Existing
metadata under the old `codex-agent-mcp` state directory is still read as a
migration fallback.

## Tools

- `agent_start`: start Agentin `a`, `b`, or `both`
- `agent_status`: structured status without raw output
- `agent_send`: send text to one running Agentin
- `agent_interrupt`: send Ctrl-C to one running Agentin
- `agent_stop`: stop Agentin `a`, `b`, or `both`
- `agent_safe_tail`: explicit capped, ANSI-stripped, redacted excerpt
- `agent_skills`: data-sparse skill inventory without file contents
- `agent_skill_match`: check whether one or all Agentinnen have a named skill
- `agent_capabilities`: summarized model, skill, and policy capabilities with a
  bounded plugin page
- `agent_scope_check`: verify write paths stay inside assignment scope
- `agent_assign`: structured, skill-aware assignment with explicit boundaries
- `agent_assign_readonly`: shortcut for read-only Exploriererin assignments
- `agent_assign_write`: shortcut for Arbeitsbiene write assignments
- `agent_assignments`: data-sparse assignment audit log
- `agent_last_assignment_status`: latest assignment metadata for one Agentin
- `agent_report_request`: ask one Agentin for a concise report
- `worktree_create_for_agent`: create an isolated git worktree for one Agentin
- `worktree_status`: capped git status and worktree metadata
- `integration_status`: repo status, diff stat, and recent assignment metadata
- `commit_ready_check`: fixed readiness checks for integration/commit
- `master_plugin_status`: plugin packaging and MCP registration status
- `agent_doctor`: structured diagnostics without raw output

`/mcp` should show `codex-master-mcp` only in the Teamleiterin/main Codex
instance. Agentin A and Agentin B intentionally do not receive Masterjet MCP
tools; they are controlled from outside and may only use native Subagentinnen
when an assignment explicitly allows it.

## Local CLI

```sh
cd /home/teladi/codex-master
python3 -m codex_master.server install          # create ~/.local/bin/codex-master-mcp + codex mcp add
python3 -m codex_master.server doctor          # smoke check (codex, tmux, state path, JSON result)
python3 -m codex_master.server uninstall       # remove mcp registration and local symlink

python3 -m codex_master.server start both --cwd /home/teladi/codex-master
python3 -m codex_master.server status
python3 -m codex_master.server capabilities all
python3 -m codex_master.server skills all
python3 -m codex_master.server skills a --include-names --limit 20 --names-offset 20 --plugins-offset 20 --plugins-limit 20
python3 -m codex_master.server skill-match all codex-security:security-scan
python3 -m codex_master.server scope-check --scope src/codex_master --write-path src/codex_master/server.py
python3 -m codex_master.server assign-readonly a --skill codex-security:security-scan --scope src/codex_master/server.py --task "Pruefe nur lesend und berichte knapp."
python3 -m codex_master.server assign-write b --scope .github/workflows --write-path .github/workflows/ci.yml --task "Haerte nur die CI-Datei."
python3 -m codex_master.server assignments all --limit 20
python3 -m codex_master.server last-assignment a
python3 -m codex_master.server integration-status
python3 -m codex_master.server commit-ready-check
python3 -m codex_master.server plugin-status
python3 -m codex_master.server send a "Kurzer Auftrag"
python3 -m codex_master.server tail a --source pane --lines 20 --chars 2000
python3 -m codex_master.server stop both
```

## Install-Contract (CLI)

`install`
- creates `~/.local/bin/codex-master-mcp` as symlink to `bin/codex-master-mcp`
- registers the command via `codex mcp add codex-master-mcp -- <link>`
- returns JSON and no agent output

`uninstall`
- unregisters from `codex mcp remove codex-master-mcp`
- removes `~/.local/bin/codex-master-mcp`
- returns JSON and no raw secret material

`doctor`
- checks availability of required tooling (`codex`, `tmux`) and MCP state directory
- reports a structured `checks` object
- redacts known secret shapes in output

`skills`
- scans each Agentin home for `SKILL.md` files in `skills/`, `plugins/cache/`,
  and `.tmp/plugins/`
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

For safer delegation, prefer `assign-readonly` and `assign-write` over
free-form `send`:

```sh
python3 -m codex_master.server assign-readonly a \
  --skill codex-security:security-scan \
  --scope src/codex_master/server.py \
  --task "Pruefe nur lesend und berichte knapp."

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

`assign-write` also gates write paths through `agent_scope_check`; a write path
outside the declared scope is rejected before anything is sent to an Agentin.
Assignment and send inputs are bounded before tmux interaction: free sends and
start prompts are capped at 12,000 characters, assignment tasks at 4,000
characters, names at 80 characters, skill refs at 300 characters, path-like
fields at 1,000 characters, and assignment lists at 50 items.

Raw logs are local debug artifacts, not normal API data. The tmux pipe writes
through a bounded local writer, `doctor` reports the configured raw-log policy,
and `tail --source log` refuses metadata paths outside the managed raw-log state.
Managed raw logs must be regular files; symlinks are not followed and are pruned
from raw-log directories. Use `tail` only when an explicit, capped,
ANSI-stripped, redacted excerpt is needed.

Model policy: Agentin A and Agentin B run on `gpt-5.4-mini` by default. Read-only
Exploriererin assignments keep that model. Arbeitsbiene write assignments are
marked for `gpt-5.3-codex-spark` in the structured assignment and audit metadata.

Agentinnen may start their own native Subagentinnen only when the assignment
uses `--allow-subagents`. Without that flag, the generated assignment explicitly
forbids nested delegation. Even with the flag, nested Agentinnen stay inside the
assigned scope and write paths; they do not use `codex-master-mcp` and they do
not commit, push, or release.

Assignments are appended to `~/.local/state/codex-master-mcp/assignments.jsonl`
as metadata only: assignment id, Agentin, role, selected model, skill match
status, scope, write paths, counts, and flags. Prompt text and Agentin responses
are not stored or returned. The audit file is retained as a bounded local JSONL
ledger: the newest 500 valid metadata records are kept, invalid legacy lines are
dropped during pruning, and the file is rewritten with `0600` permissions.

Use `tail` only when an explicit, capped excerpt is needed. Normal status and
send operations do not return Agentin output.

## Plugin

This repo is also a local Codex plugin:

- `.codex-plugin/plugin.json`: plugin metadata and Codex UI information
- `.mcp.json`: starts `codex-master-mcp` from this repo without package install
- `skills/codex-master-fleet/SKILL.md`: Teamleiterin skill for the Masterjet

The plugin is intended for the main/Teamleiterin Codex instance. Agentin A and
Agentin B should keep their separate worker skill and should not receive
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
