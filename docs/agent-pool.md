# Agentinnen Pool

`codex-master` can install a sleeping Codex Agentinnen pool from a JSON spec.
The installer creates per-Agentin `CODEX_HOME` directories, a regular executable
`codex` wrapper, a minimal `config.toml`, private runtime directories, and a
pool marker. It does not start Agentinnen.

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

Auth is intentionally not copied during normal install. To inspect a mass-copy
operation first, omit `--yes`:

```sh
./bin/codex-master-mcp pool copy_auth --spec codex-agent-pool.json --from-agent a1 --to a-series
./bin/codex-master-mcp pool copy_auth --spec codex-agent-pool.json --from-agent a1 --to a-series --yes
```

`copy_auth` copies only `auth.json`, never returns its content, skips the source
Agentin, and does not overwrite existing target auth files unless `--overwrite`
is set.

Destruction is guarded. The command removes only Agentin entries described by
the spec, requires `--yes`, and also requires the installed pool marker unless
`--force` is passed:

```sh
./bin/codex-master-mcp pool destroy_pool --spec codex-agent-pool.json --yes
```
