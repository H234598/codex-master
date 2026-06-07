---
name: codex-master-fleet
description: Use when managing the local codex-master-mcp Masterjet, Codex Agentinnen A/B, Bienen, Arbeitsbienen, Exploriererinnen, fleet variables, plugin status, or persistent feminine agent delegation rules.
metadata:
  short-description: Manage codex-master-mcp and the local Agentinnen fleet
---

# Codex Master Fleet

Use this skill in the Teamleiterin/main Codex instance when the user refers to
the Masterjet, `codex-master`, `codex-master-mcp`, Agentin A/B, Bienen,
Arbeitsbienen, Exploriererinnen, fleet rules, plugin status, telint imports, or
the persisted delegation templates.

This skill is for the controlling instance. Do not install it into Agentin A/B
unless the intent is to make that instance a Teamleiterin.

## Model Policy

- Agentin A and Agentin B run on `gpt-5.4-mini` by default with medium
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
- Default fleet size is 2-3 Bienen. Maximum is 6, only for independent tasks.
- Exploriererinnen read, analyze, and report concise context packages only.
- Arbeitsbienen may write only in assigned files or isolated workspaces.
- Before assigning writes, inspect `git status --short` and avoid overlapping
  write scopes.
- Security is more important than performance; still keep performance in mind.
- Version all coding steps. Commit after 10 successful fixes, push after 10
  commits, release after 10 pushes. Push/release only with green tests and no
  known critical findings.
- Agentin A/B may start native Subagentinnen only when the assignment explicitly
  allows it. Nested Subagentinnen must stay inside the assigned scope and write
  paths. They must not use `codex-master-mcp` to control the fleet.
- Do not manually start Agentin A/B with the same `CODEX_HOME` while the
  Masterjet manages them. Use `doctor` if a terminal looks stuck; `start`
  blocks when an Agentin home is already used externally, including when a
  Masterjet tmux session already exists. Agentin runners must be regular
  executable files, not symlinks.
- A stopped Agentin is a normal informational `doctor` session state, not a
  failed health check.

## MCP Visibility

In `/mcp`, the main Codex instance should show `codex-master-mcp`. Agentin A and
Agentin B intentionally should not show the Masterjet MCP tools. If a standard
instance says that Master MCP Tools are none, then either that instance is not
the Teamleiterin, or `codex-master-mcp` is not installed/configured there.

## Masterjet Control

Prefer structured tools over raw `send`:

```sh
cd /home/teladi/codex-master
./bin/codex-master-mcp doctor
./bin/codex-master-mcp status
./bin/codex-master-mcp start both --cwd /home/teladi/codex-master
./bin/codex-master-mcp capabilities all
./bin/codex-master-mcp skills all
./bin/codex-master-mcp skills a --include-names --limit 20 --names-offset 20 --plugins-offset 20 --plugins-limit 20
./bin/codex-master-mcp skill-match all codex-security:security-scan
./bin/codex-master-mcp scope-check --scope src --write-path src/codex_master/server.py
./bin/codex-master-mcp assign-readonly a --skill codex-security:security-scan --scope src/codex_master/server.py --task "Pruefe nur lesend und berichte knapp."
./bin/codex-master-mcp assign-write b --skill github:gh-fix-ci --scope .github/workflows --write-path .github/workflows/ci.yml --task "Haerte nur die CI-Datei."
./bin/codex-master-mcp assignments all --limit 20
./bin/codex-master-mcp last-assignment a
./bin/codex-master-mcp report-request a
./bin/codex-master-mcp integration-status
./bin/codex-master-mcp commit-ready-check
./bin/codex-master-mcp plugin-status
```

Data minimization:

- `status`, `start`, `send`, `assign-*`, `doctor`, `skills`, `capabilities`,
  and `plugin-status` do not return Agentin terminal output.
- `capabilities` returns a bounded first plugin page plus counts/truncation
  flags, not a complete broad plugin inventory.
- `skills` returns bounded plugin/name pages plus total counts, offsets, limits,
  and truncation flags so callers can deliberately enumerate more pages without
  broad dumping. Symlinked skill roots and symlinked `SKILL.md` files are
  ignored instead of being followed.
- `assignments` and `last-assignment` return only assignment metadata. They
  must not return prompt text, Agentin responses, or local audit file paths.
- Assignment audit retention is bounded to the newest 500 valid metadata
  records in a local `0600` JSONL file. Assignment-log reads require regular
  files, are capped, and use generic errors. Private state appends refuse
  symlink paths, and private state file/directory errors must not expose local
  state paths. Agentin metadata is written atomically, and temporary replace
  files are created with no-follow exclusive semantics. Agentin metadata reads
  reject symlinked and oversized files, and metadata presence checks do not
  follow symlinks. Metadata read errors and legacy source markers must not
  expose local file paths. Managed state directories must be real directories,
  not symlinks or regular files.
- Raw logs are local debug artifacts. New raw logs are bounded to 5 MiB per
  file, managed raw-log directories retain at most 20 files by default, and
  log-tail metadata paths must stay inside managed raw-log state. Prepared
  raw-log files are created with no-follow exclusive semantics, and raw-log
  symlinks are not followed. The direct raw-log writer verifies real managed
  state directories before accepting log input, and symlinked legacy raw-log
  directories are ignored. Safe-tail log reads only regular raw-log files.
  Tmux control errors are redacted and bounded before they are returned or
  raised. Public tool responses expose raw-log presence without returning local
  raw-log paths. Failed starts must remove prepared raw-log files. External
  `tmux`, `git`, and `codex mcp` subprocess calls must be timeout-bounded.
  MCP registration checks must compare the exact `command:` field reported by
  `codex mcp get`, not substring-match broad command output.
- Assignment inputs are bounded before tmux interaction: sends/start prompts
  12,000 chars, tasks 4,000 chars, names 80 chars, skill refs 300 chars,
  path-like fields 1,000 chars, and assignment lists 50 items. MCP boolean and
  integer arguments are type-checked; stringified values are rejected instead of
  being coerced. Incoming MCP frames are capped at 1 MiB before JSON parsing.
  Tool and RPC error texts are ANSI-stripped, redacted, and length-bounded
  before they are returned. `tools/call` validates tool names, object-shaped
  params and arguments, unknown argument names, required fields, value types,
  enums, and declared bounds before dispatch.
- Worktree creation must reject existing targets, including broken symlinks,
  and require every target parent directory to be a real directory.
- Worktree status must reject symlinks and non-directory targets before running
  `git status`.
- Install and uninstall symlink operations must require the install-path parent
  chain to be real directories. Install, uninstall, and doctor must resolve
  install symlinks defensively: broken, looping, or unreadable symlinks are
  non-matching, and doctor reports an unreadable target marker instead of
  crashing.
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
