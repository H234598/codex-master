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
counts and state markers.

`pool install` is idempotent. It creates missing Agentin homes, regular
executable wrappers, minimal configs, runtime directories, and an installed pool
marker. It does not start Agentinnen and does not copy auth by default.

`pool status` counts installed homes, wrappers, configs, auth files, and shared
asset symlinks. It returns `pool_root: not_returned`, not local paths.

`pool copy_auth` copies one source `auth.json` to many installed Agentinnen.
Without `--yes` it is a dry-run and only reports copy counts.

```sh
./bin/codex-master-mcp pool copy_auth --spec codex-agent-pool.json --from-agent a1 --to a-series
./bin/codex-master-mcp pool copy_auth --spec codex-agent-pool.json --from-agent a1 --to a-series --yes
```

`pool destroy_pool` removes only the Agentin entries described by the spec. It
requires `--yes` and the installed pool marker unless `--force` is passed.

## Auth Rules

Auth is intentionally not copied during normal install. To inspect a mass-copy
operation first, omit `--yes`; to apply it, repeat the same command with
`--yes`.

`copy_auth`:

- reads only `<pool-root>/<from-agent>/auth.json`
- requires the source Agentin to be part of the pool spec
- resolves the target selector through the same spec
- skips the source Agentin if the target selector includes it
- skips missing target homes
- skips existing target `auth.json` unless `--overwrite` is set
- writes target auth files as private regular files
- never returns auth file content
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
