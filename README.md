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
state files under `~/.local/state/codex-agent-mcp/raw/`. MCP tool responses do
not return raw output by default.

## Tools

- `agent_start`: start Agentin `a`, `b`, or `both`
- `agent_status`: structured status without raw output
- `agent_send`: send text to one running Agentin
- `agent_interrupt`: send Ctrl-C to one running Agentin
- `agent_stop`: stop Agentin `a`, `b`, or `both`
- `agent_safe_tail`: explicit capped, ANSI-stripped, redacted excerpt

## Local CLI

```sh
/home/teladi/codex-master/bin/codex-agent-mcp start both --cwd /home/teladi/codex-master
/home/teladi/codex-master/bin/codex-agent-mcp status
/home/teladi/codex-master/bin/codex-agent-mcp send a "Kurzer Auftrag"
/home/teladi/codex-master/bin/codex-agent-mcp tail a --source pane --lines 20 --chars 2000
/home/teladi/codex-master/bin/codex-agent-mcp stop both
```

## MCP registration

```sh
ln -sfn /home/teladi/codex-master/bin/codex-agent-mcp /home/teladi/.local/bin/codex-agent-mcp
codex mcp add codex-agent-mcp -- /home/teladi/.local/bin/codex-agent-mcp
```

The installed executable is intended to be a symlink to
`/home/teladi/codex-master/bin/codex-agent-mcp`, so changes in this repo are used
directly.

## Checks

```sh
PYTHONPATH=src python3 -m compileall -q src tests
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

The same checks run in GitHub Actions via `.github/workflows/ci.yml`.
