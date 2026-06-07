# Auth Copy

`codex-master` treats authentication data as per-Agentin state. The pool spec
can mark source homes as authenticated, but it does not contain credentials.
The credential-bearing file is the real `auth.json` inside a `CODEX_HOME`.

Example source files:

```text
~/.codex-agents/a1/auth.json
~/.codex-agents/b1/auth.json
```

## What The Command Does

`pool copy_auth` copies one source `auth.json` into a selected group of
installed Agentin homes:

```sh
./bin/codex-master-mcp pool copy_auth \
  --spec codex-agent-pool.json \
  --from-agent a1 \
  --to a-series
```

That first command is a dry-run. It returns counts only:

```json
{
  "dry_run": true,
  "source_agent": "a1",
  "target_selector": "a-series",
  "target_count": 99,
  "copyable_count": 99,
  "copied_count": 0,
  "skipped_existing_count": 0,
  "skipped_missing_home_count": 0,
  "auth_content": "not_returned",
  "pool_root": "not_returned"
}
```

To actually copy, repeat the same command with `--yes`:

```sh
./bin/codex-master-mcp pool copy_auth \
  --spec codex-agent-pool.json \
  --from-agent a1 \
  --to a-series \
  --yes
```

## Selectors

The target selector is resolved through `codex-agent-pool.json`.

Common selectors:

- `a-series`: all A-series Agentinnen
- `b-series`: all B-series Agentinnen
- `c-series`: all C-series Agentinnen
- `all`: every Agentin from the spec
- `a2`: one concrete Agentin

If the selector includes the source Agentin, the source is skipped. For example,
`--from-agent a1 --to a-series` copies to `a2..a100`, not back to `a1`.

## Safety Model

The copy path is deliberately conservative:

- `auth.json` must be a regular file, not a symlink
- oversized source files are rejected
- target homes must be real directories, not symlinks
- existing target auth files are skipped unless `--overwrite` is set
- target files are written as private files
- command responses never include auth content
- command responses never include local pool paths

This preserves the main data-minimization rule: callers can see what is possible
and what happened, but they do not receive the credential material.

## Overwrite

By default, existing target auth is left untouched:

```sh
./bin/codex-master-mcp pool copy_auth \
  --spec codex-agent-pool.json \
  --from-agent b1 \
  --to b-series \
  --yes
```

Use `--overwrite` only when replacing existing target auth is intentional:

```sh
./bin/codex-master-mcp pool copy_auth \
  --spec codex-agent-pool.json \
  --from-agent b1 \
  --to b-series \
  --yes \
  --overwrite
```

## Install-Time Auth Copy

`pool install` can run the same explicit auth copy after creating or refreshing
homes:

```sh
./bin/codex-master-mcp pool install \
  --spec codex-agent-pool.json \
  --target-dir "$HOME/.codex-agents" \
  --copy-auth-from a1 \
  --copy-auth-to a-series
```

That is still dry-run for auth unless `--yes` is present:

```sh
./bin/codex-master-mcp pool install \
  --spec codex-agent-pool.json \
  --target-dir "$HOME/.codex-agents" \
  --copy-auth-from a1 \
  --copy-auth-to a-series \
  --yes
```

## Why Not Link Auth

Symlinking `auth.json` is not the intended model. It crosses the no-follow trust
boundary and makes it harder to reason about which Agentin owns which secret.

Hardlinking is also not the intended model. It keeps one shared inode behind
multiple filenames. If one Agentin updates, rotates, truncates, or corrupts that
file, every hardlinked Agentin sees the same change.

Auth files are small. Copying them costs little disk space and gives each
Agentin an independent failure domain.
