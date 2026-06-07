# codex-master

Local MCP wrapper for controlling two existing Codex CLI homes:

- `/home/teladi/.codex-agent-a`
- `/home/teladi/.codex-agent-b`

The wrapper starts both instances through their existing `codex` launcher files
with:

```sh
--yolo -s danger-full-access --search
```

It uses `tmux` as the PTY backend. Full terminal output is written only to local
state files under `~/.local/state/codex-master-mcp/raw/`. MCP tool responses do
not return raw output by default. Existing metadata under the old
`codex-agent-mcp` state directory is still read as a migration fallback.

## Tools

- `agent_start`: start Agentin `a`, `b`, or `both`
- `agent_status`: structured status without raw output
- `agent_send`: send text to one running Agentin
- `agent_interrupt`: send Ctrl-C to one running Agentin
- `agent_stop`: stop Agentin `a`, `b`, or `both`
- `agent_safe_tail`: explicit capped, ANSI-stripped, redacted excerpt
- `agent_skills`: data-sparse skill inventory without file contents
- `agent_doctor`: structured diagnostics without raw output

## Local CLI

```sh
cd /home/teladi/codex-master
python3 -m codex_master.server install          # create ~/.local/bin/codex-master-mcp + codex mcp add
python3 -m codex_master.server doctor          # smoke check (codex, tmux, state path, JSON result)
python3 -m codex_master.server uninstall       # remove mcp registration and local symlink

python3 -m codex_master.server start both --cwd /home/teladi/codex-master
python3 -m codex_master.server status
python3 -m codex_master.server skills all
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
- returns counts, roots, system-skill names, and plugin skill counts
- returns no skill file contents and no Agentin terminal output

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

Use `tail` only when an explicit, capped excerpt is needed. Normal status and
send operations do not return Agentin output.

## Checks

```sh
PYTHONPATH=src python3 -m compileall -q src tests
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

The same checks run in GitHub Actions via `.github/workflows/ci.yml`.
