# Changelog

## 0.10.5 - 2026-08-16

### Added

- Fleet Registry v2 overview with bounded account, series, provider, and
  usage-contract data.
- G-Serie materialization, migration, recovery, and fleet-management
  operations with private atomic state writes.
- Sanitized hourly Goddess reports with UTC buckets, bounded backfill,
  retries, single-leader locking, Assignment-/Gemini-Result-/Hive task
  aggregation, CLI/MCP access, and hardened optional user timer.
- Added private bounded Hive queue/completion event persistence. The runtime
  exposes `HiveEventStore`; the explicit Queen adapter records queue and final
  status evidence without persisting payloads.
- The persistent admission journal can now emit idempotent `executing` and
  `completed` Hive events through an explicitly injected `HiveEventStore`.

### Security and stability

- Public status, applet, report, and integration outputs exclude prompts,
  responses, credentials, paths, and raw process output.
- Resource-pressure and Ollama admission gates remain active below the global
  ten-Bee cap.
- Local Ollama benchmark output is bounded during reading and cannot grow the
  Master process without limit.
- MCP startup/tools probes now bound stdout to 256 KiB and terminate the
  isolated process group on timeout or overflow.
- Persistent admission state is read through a bounded `MAX+1` binary read
  after metadata validation, closing a growth race without unbounded JSON I/O.
- Generic command execution now reads stdout/stderr concurrently with 2 MiB /
  256 KiB caps and preserves timeout, unavailable, and `check=True` semantics.
- tmux command execution uses the same bounded stdout/stderr reader while
  preserving bounded stdin for paste-buffer operations.
- Hive repository validation now reads Git stdout with a 64 KiB limit and
  terminates the isolated process group on overflow or timeout; invalid UTF-8
  output fails closed.
- Reporter state loading now rejects symlinked parent directories before
  reading state.
- Hive event reads use bounded locked JSONL, exact schema validation, ID/UTC
  validation, and fail-closed handling for tampered `raw_output` fields.
- Pure Hive transition helpers remain side-effect-free; unconnected producers
  still leave missing completion evidence visible to the reporter. Event IDs
  make retries idempotent.

### Verification

- `pytest -q`: 2059 passed, 291 subtests passed.
- Ruff, Python compilation, `git diff --check`, systemd unit verification,
  and Cinnamon applet tests: 101 passed.
