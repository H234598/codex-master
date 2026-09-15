# Active-documentation consolidation record

**Migration date:** 2026-09-15

**Base examined:** `b5def7d6156d7862606a0edcbd7226652cf4833f`

**Current-product comparison:** `git diff --name-only`
`b5def7d6156d7862606a0edcbd7226652cf4833f..origin/main` showed the unassessed
BUS-S1 files `src/the_hive/hive/bus_store.py` and
`tests/test_hive_bus_store.py`. They are outside this record's scope. A
separate path-limited comparison found no change in the concrete documentation
evidence cited here: `bin/`, `scripts/`, `systemd/`, `.github/`, project and
MCP/plugin manifests, checked-in configuration/catalog files, or the man-page
source. This is not a claim about every other source or test surface.

This is the preservation-and-disposition record for the active documentation
that was shortened during the The-Hive documentation migration. It is separate
from [the Wiki consolidation record](wiki-consolidation.md): the latter covers
the removed `docs/wiki/` publishing layout, while this page covers reductions
to ordinary active documentation.

`Erhalten` means that the stated information is represented in a named current
section. `Bewusst nicht als aktive Doku übernommen` is a deliberate, final D136
disposition, not an assertion that the historical statement was false: its
particular old binary/module/command, private deployment fact, or
live/provider/desktop claim could not safely be promoted to a current operator
instruction. A current source module or focused test can establish an
implementation contract without establishing a complete, authorized operator
interface; such a detail is not silently preserved by Git history.

## `README.md` in the base

| Base section / lines | Disposition | Current destination or precise reason |
|---|---|---|
| Project identity and former Wiki navigation, 1–11 | Erhalten / konsolidiert | Current [`README.md`](../../README.md), “What is in this repository” (The Hive identity and navigation), plus [Wiki consolidation record](wiki-consolidation.md), “Section-level parity check”. The assertion that `docs/wiki/Home.md` was canonical was intentionally replaced because ordinary `docs/` is now the sole navigation. |
| Resource monitor H4 operator lifecycle, 12–83 | Erhalten in a separate recovery package | The old `codex-master-resource-monitor.service` name and old wrapper command are not copied. B5 has the renamed `bin/the-hive-resource-monitor`, `systemd/user/the-hive-resource-monitor.service`, and `scripts/the-hive-hive-hourly-probe-install`. The dedicated target is [`docs/operations/resource-monitor.md`](../operations/resource-monitor.md), “The Hive Resource Monitor (H4)” (Recovery worker G). |
| Private A/B/C home inventory, selectors, and declared authenticated homes, 84–112 | Bewusst nicht als aktive Doku übernommen | These lines name concrete private homes, auth state, and a historical `CODEX_MASTER_AGENT_SELECTOR_SERIES` workflow. The current pool page deliberately states only the checked-in series and marks runtime/auth state unknown: [`docs/agent-pool.md`](../agent-pool.md), “Geltungsbereich und Status”. Reproducing private local inventory as current fact would be unsafe/unverifiable. |
| Wrapper defaults, tmux/log behavior, lease, auth, watchdog, and status detail, 114–243 | Erhalten in boundary form; remaining detail bewusst nicht übernommen | [`docs/agent-pool.md`](../agent-pool.md), “Konfigurations- und Vertrauensmodell”, [`docs/auth-copy.md`](../auth-copy.md), “Grenze”, [`docs/security/hive-security.md`](../security/hive-security.md), and [`docs/operations/runbook.md`](../operations/runbook.md), “Safe operational sequence”, preserve the non-symlink, auth, bounded-output, lease, and revalidation boundaries. B5 still has lifecycle tools in `the_hive.server`, but the base's tmux timings, private paths, and `codex-master` wrapper defaults do not establish a complete authorized operator interface; turning them into a new recipe would be unsafe. |
| Fleet accounts, supplied Gemini tier tables, OAuth setup, and credential-sync commands, 244–341 | Bewusst nicht als aktive Doku übernommen | The lines depend on supplied local dashboard exports, named private accounts, `codex_master` command paths, a private token-file migration, and install/credential operations. The current source can show code paths but cannot re-attest the quoted account tiers, spend limits, dashboard data, or a safe operator sequence. [`docs/configuration.md`](../configuration.md), “Current checked-in state”, retains the safe source-input boundary without those live/provider claims. |
| Gemini headless-job isolation, rate limiting, and control-center/Applet bounds, 342–374 | Bewusst nicht als aktive Doku übernommen | B5 still contains `src/the_hive/fleet_service.py` Gemini gates, `src/the_hive/server.py` headless routing, and focused tests, so this is implementation evidence—not a missing binary. It does not provide an authorized provider-account, project-reservation, or desktop-control sequence. [`README.md`](../../README.md), “Status and limitations”, and [`docs/configuration.md`](../configuration.md), “Current checked-in state”, retain the safe current statement that provider/account evidence is unknown; copying the base's provider-specific operational detail would be unsafe. |
| Agent/tool inventory and admission-store/selection-service contract, 375–461 | Erhalten in boundary form; remaining detail bewusst nicht übernommen | [`docs/control-plane.md`](../control-plane.md), “Checked-in contract layers”, [`docs/security/hive-security.md`](../security/hive-security.md), [`docs/resolver.md`](../resolver.md), and [`docs/operations/runbook.md`](../operations/runbook.md), “Start with the intended interface”, retain the authority/admission/selection/output contract. B5's individual tool entries in `src/the_hive/control_catalog.py` and `src/the_hive/server.py` are real, but the base's legacy direct-tool inventory is not a complete safe interface for an unknown installed runtime; no new active command reference is created. |
| Hive control-plane overview and linked source material, 462–485 | Erhalten / consolidated | [`docs/control-plane.md`](../control-plane.md), “Checked-in contract layers” and “Fail-closed boundary”; [`docs/operations/hive-operations.md`](../operations/hive-operations.md), “Verifizierter Umfang”; and [`docs/security/hive-security.md`](../security/hive-security.md). The legacy `codex_master` package spelling is not active identity. |
| Further tool inventory, namespace/plugin status, pool-management surface, and local `/mcp` advice, 486–540 | Erhalten in boundary form; remaining detail bewusst nicht übernommen | [`docs/agent-pool.md`](../agent-pool.md), [`docs/auth-copy.md`](../auth-copy.md), [`docs/installation.md`](../installation.md), “Supported repository evidence”, and [`docs/operations/runbook.md`](../operations/runbook.md), “Start with the intended interface”, cover the current boundaries. B5 retains `app-bridge-status`, `plugin-status`, and `namespace-status`, but a source declaration does not make the base's client-specific namespace, plugin-cache, or direct-command procedure portable or safe. |
| Central resolver narrative and fixed model/lifecycle tuples, 541–610 | Erhalten with deliberate non-duplication | [`docs/resolver.md`](../resolver.md), “Current source-backed inputs”, “Selection boundary”, and “Historical Wiki selection-flow record” retain offer, fallback, and revalidation meaning. Exact model matrices and role tuples are intentionally not recopied: current JSON catalogs are the normative source and a second prose matrix would become stale. |
| Spawn-offer contract and remote-backend prerequisites, 611–691 | Bewusst nicht als aktive Doku übernommen | `agent_spawn_offers` remains in `src/the_hive/server.py`, `src/the_hive/control_catalog.py`, and focused tests, but B5 does not supply an authorized installed-runtime operator interface for the base's resource-pressure thresholds, local routing values, or remote-backend prerequisites. [`docs/resolver.md`](../resolver.md), “Selection boundary”, preserves the safe advisory/non-reservation/revalidation rule; detailed old `codex_master` usage is not recopied. |
| Checkout command block, 693–748 | Bewusst nicht als aktive Doku übernommen | Every executable example invokes `codex_master`, `codex-master-mcp`, old repo paths, or installation/reload actions. The current attested wrapper explicitly is not a checkout command; see [`docs/installation.md`](../installation.md), “Supported repository evidence”, and [`docs/operations/runbook.md`](../operations/runbook.md), “Start with the intended interface”. |
| Agent-pool spec details and Cinnamon-installer paragraph, 749–812 | Erhalten in boundary form; remaining detail bewusst nicht übernommen | The pool format/trust boundary and auth-copy facts are retained in [`docs/agent-pool.md`](../agent-pool.md) and [`docs/auth-copy.md`](../auth-copy.md). Concrete current-home counts, historical direct commands, and private account paths are deliberately omitted. Although `scripts/the-hive-cinnamon-applet` exists, its installer is a desktop mutation with no D136-authorized operating procedure. |
| Cinnamon Applet: Flottenmanagement, 813–936 | Bewusst nicht als aktive Doku übernommen | B5 contains `cinnamon/applets/the-hive@H234598/`, `scripts/the-hive-cinnamon-applet`, and focused tests. That proves a static implementation, not the old document's desktop/session/hook-trust, D-Bus, reload, or installed-Xlet state. [`docs/operations/runbook.md`](../operations/runbook.md), “Mutation and release boundaries”, retains the evidence-first rule; reproducing the base workflow would be unsafe. |
| Install, uninstall, doctor, watchdog, timeout, skills, and Goddess timer detail, 937–1073 | Erhalten in boundary form; remaining detail bewusst nicht übernommen | [`docs/installation.md`](../installation.md), “Supported repository evidence”, [`docs/releases.md`](../releases.md), “Source-backed release boundary”, [`docs/operations/goddess-reporting.md`](../operations/goddess-reporting.md), “Verifizierter Quellumfang”, and [`docs/operations/runbook.md`](../operations/runbook.md) retain the attested-release, no-checkout, status-first, and mutation boundaries. B5's `the-hive-watchdog` source/unit does not establish the base's activation or health procedure for any installed user; old unit names and commands are deliberately excluded. |
| App Bridge, 1074–1104 | Bewusst nicht als aktive Doku übernommen | `master_app_bridge_status`, `.app.json`, and the current plugin manifest exist in B5, but the base's connector/HTTP and direct `codex_master` procedure has no verified deployed endpoint or current client registration. [`README.md`](../../README.md), “What is in this repository”, retains the static MCP configuration boundary without presenting a connector operation. |
| Steering Skills, assignments, lease/input limits, raw-log and worktree guidance, 1105–1239 | Erhalten in boundary form; remaining detail bewusst nicht übernommen | [`docs/security/hive-security.md`](../security/hive-security.md), [`docs/agent-pool.md`](../agent-pool.md), and [`docs/operations/runbook.md`](../operations/runbook.md), “Safe operational sequence”, retain explicit scopes, reviews, auth, data minimization, and lease/revalidation principles. The current `the_hive` code and tests do not make the base's old `codex_master` skill names, prompts, size limits, or mutation recipes a safe active operator surface. |
| Plugin description, 1241–1258 | Bewusst nicht als aktive Operator-Dokumentation übernommen | The base claims a checkout-started legacy plugin and `codex-master-mcp` registration, which conflicts with current attested-runtime guidance and the documented CI manifest-name conflict. Current static identity is covered by [`README.md`](../../README.md), “What is in this repository”; no installation or Marketplace behavior is claimed. |
| Checks and CI claims, 1259–1276 | Erhalten with narrowed, source-backed scope | [`docs/development.md`](../development.md), “Focused verification” and “CI status boundary”, and [`docs/operations/ci.md`](../operations/ci.md), “Bekannter Blocker” / “Prüfgrenze”. The old full-suite and legacy-wrapper commands are not current documentation, and no green CI result is inferred. |

## `docs/agent-pool.md` in the base

| Base section / lines | Disposition | Current destination or precise reason |
|---|---|---|
| Introduction and pool-spec boundary, 1–12 | Erhalten | [`docs/agent-pool.md`](../agent-pool.md), “Geltungsbereich und Status”. |
| Default layout, authenticated-home assertions, selector rotation, and direct selector commands, 13–61 | Bewusst nicht als aktive Doku übernommen | These examples combine private `~/.codex-agents` contents, runtime authentication assertions, and old `codex-master-mcp` commands. The current page preserves the checked-in series but correctly leaves local installation/auth unknown. |
| Default/custom install and shortcut commands, 63–86 | Bewusst nicht als aktive Doku übernommen | They invoke the legacy wrapper or a state-changing installer. Current [`docs/agent-pool.md`](../agent-pool.md), “Verifizierte Schnittstellengrenze”, identifies those operations without publishing an execution sequence. |
| Commands, validation/install/status, tmux readiness, live-data assignment, copy and destruction, 87–144 | Erhalten in boundary form | Current [`docs/agent-pool.md`](../agent-pool.md), “Verifizierte Schnittstellengrenze” and “Konfigurations- und Vertrauensmodell” retains parser, non-symlink, no-start, mutation-confirmation, data-sparse, and auth-source constraints. Old direct command forms and current local-status assertions are not instructions. |
| Auth Rules and copy-auth safeguards, 145–193 | Erhalten | [`docs/auth-copy.md`](../auth-copy.md), “Grenze” and “Explizite Kopie und Aktualisierung”, plus [`docs/agent-pool.md`](../agent-pool.md), “Konfigurations- und Vertrauensmodell”. Absolute local profile locations are not reproduced. |
| Destruction commands, 194–207 | Erhalten in boundary form | [`docs/agent-pool.md`](../agent-pool.md), “Verifizierte Schnittstellengrenze” identifies `destroy_pool` as confirmation-gated mutation; old executable examples are intentionally excluded. |

## `docs/auth-copy.md` in the base

| Base section / lines | Disposition | Current destination or precise reason |
|---|---|---|
| Per-agent auth boundary and profile mapping, 1–25 | Erhalten | [`docs/auth-copy.md`](../auth-copy.md), “Grenze”. The base's absolute profile and target paths are private deployment details, so current documentation names no credential path. |
| What The Command Does, including JSON dry-run example and `--yes` command, 26–67 | Erhalten in boundary form | [`docs/auth-copy.md`](../auth-copy.md), “Explizite Kopie und Aktualisierung”, retains dry-run versus credential mutation and output-redaction facts. The legacy wrapper invocation and sample counts are not current instructions or runtime evidence. |
| Selectors, 68–82 | Bewusst nicht als aktive Operator-Anleitung übernommen | Selector names and concrete range examples are old operational interface detail. The current page describes the configured selector check but does not create a command recipe. |
| Safety Model, 83–100 | Erhalten | [`docs/auth-copy.md`](../auth-copy.md), “Explizite Kopie und Aktualisierung”, bullets 1–4. |
| Overwrite, 101–123 | Erhalten | [`docs/auth-copy.md`](../auth-copy.md), “Explizite Kopie und Aktualisierung”, states the existing target is retained without explicit overwrite. Legacy command spellings are omitted. |
| Install-Time Auth Copy, 124–148 | Bewusst nicht als aktive Operator-Anleitung übernommen | The sequence uses old wrapper paths and a provisioning-time copy workflow. The current pages document the source-backed fail-closed behavior but do not authorize credential writes. |
| Why Not Link Auth, 149–159 | Erhalten | [`docs/auth-copy.md`](../auth-copy.md), “Explizite Kopie und Aktualisierung”, last bullet, and [`docs/agent-pool.md`](../agent-pool.md), “Konfigurations- und Vertrauensmodell”. |

## `docs/account-aware-selection.md` in the base

| Base section / lines | Disposition | Current destination or precise reason |
|---|---|---|
| Privacy, DP/SP separation, preview/admission, typed usage, reset anchor, 1–26 | Erhalten / consolidated | [`docs/account-aware-selection.md`](../account-aware-selection.md), “Aktueller Produktstand”, and [`docs/operations/selection-operations.md`](../operations/selection-operations.md), “Status”. The old `codex_master` command spelling is not retained. |
| Private policy loader and fail-closed policy modes, 28–47 | Erhalten | [`docs/account-aware-selection.md`](../account-aware-selection.md), “Policy-Grenze”. The active loader path is `the_hive.selection.config.load_selection_policy`; the old module spelling is historical only. |
| Resolver offer, generation, account availability, visible fallback, and authority non-escalation, 49–73 | Erhalten / consolidated | [`docs/resolver.md`](../resolver.md), “Current source-backed inputs”, “Selection boundary”, and “Historical Wiki selection-flow record”; [`docs/operations/selection-operations.md`](../operations/selection-operations.md), “Resolver und Grenzen”. Exact static model behavior remains in the checked-in catalogs, not a duplicate prose matrix. |

## `docs/operations/hive-operations.md` in the base

| Base section / lines | Disposition | Current destination or precise reason |
|---|---|---|
| Scope, old local diagnostic command block, global dispatch, pause, emergency Queen, and state boundary, 1–53 | Erhalten in boundary form | [`docs/operations/hive-operations.md`](../operations/hive-operations.md), all three current sections, and [`docs/control-plane.md`](../control-plane.md), “Fail-closed boundary”. The base's old executable commands are deliberately not copied because the attested wrapper is not a checkout command. |
| Runtime assembly, events, admission/journal/recovery, executor and assignment bridges, 54–127 | Erhalten in boundary form; remaining detail bewusst nicht übernommen | [`docs/control-plane.md`](../control-plane.md), “Checked-in contract layers” and “Evidence limit”, and [`docs/operations/hive-operations.md`](../operations/hive-operations.md), “Aktuelle Fail-closed-Grenzen”, preserve the current typed runtime/admission/event and missing-executor boundaries. B5's named `the_hive.hive` mechanisms and tests do not make the base's detailed callback/journal wiring a safe productive procedure; no callback recipe is transferred. |
| Obsidian section/annotation response protocol, 128–201 | Bewusst nicht als aktive Produktdokumentation übernommen | This is a document-editing protocol, not product/operator behavior, and cites an Annotation Marker sidecar workflow not used by current normal repository navigation. It must not be made an implicit The-Hive runtime contract. |
| Generator/provider projection and old `src/codex_master/markdown` source path, 202–219 | Bewusst nicht als aktive Dokumentation übernommen | The named base path no longer exists. B5 has `src/the_hive/fleet_markdown.py` and `src/the_hive/hive_policy.py`, but the base claim's exact canonical path and test command are invalid. A new policy-projection document would need a separate source-led scope; it cannot be preserved by renaming the old command. |
| OpenAI stickiness/reset policy old-path reference, 220–226 | Bewusst nicht als aktive Dokumentation übernommen | It only delegates to the obsolete `src/codex_master/markdown/common.md` path. Current source may contain a differently located policy, but this base statement has no safe current target or verified operating procedure. |

## `docs/operations/selection-operations.md` in the base

| Base section / lines | Disposition | Current destination or precise reason |
|---|---|---|
| Preview/rollout/usage guidance, 1–26 | Erhalten in boundary form | [`docs/operations/selection-operations.md`](../operations/selection-operations.md), “Status”, and [`docs/account-aware-selection.md`](../account-aware-selection.md), “Aktueller Produktstand”. The old direct `python -m codex_master` preview invocation and rollout order are not active instructions. |
| Class/lifecycle/model/reasoning matrix and lifecycle administration rule, 27–94 | Erhalten with deliberate non-duplication | [`docs/resolver.md`](../resolver.md) carries current input, fallback, and evidence boundaries; catalogs remain the authoritative matrix. Exact base tuples and its role-administration statement are not recopied because they form a stale-prone second matrix and use legacy product identity. |
| Emergency token burn and Spark quota steering, 95–114 | Bewusst nicht als aktive Doku übernommen | B5 contains `src/the_hive/limit_tracker.py`, `src/the_hive/limit_tracker_contract.py`, and focused tests, so reversible priority state is source evidence. It does not establish an authorized account, actual quota/emergency observation, or operator decision procedure. [`docs/account-aware-selection.md`](../account-aware-selection.md), “Aktueller Produktstand”, preserves the current fail-closed/preview-only selection limit; the base's account-specific steering sequence is not copied. |

## `docs/operations/hive-pilot-provisioner.md` in the base

| Base section / lines | Disposition | Current destination or precise reason |
|---|---|---|
| Entire provisioner description and historical plan/apply/verify/kill-switch/rollback examples, 1–82 | Erhalten in boundary form | [`docs/operations/hive-pilot-provisioner.md`](../operations/hive-pilot-provisioner.md), “Verifizierter Quellumfang”, “Blockierende Gates”, and “Handlungsgrenze”. The old script name, old canonical repository/Origin assertion, and state-changing command examples are deliberately absent; the current page identifies the current script and explicitly withholds an execution sequence. |

## `docs/operations/goddess-reporting.md` in the base

| Base section / lines | Disposition | Current destination or precise reason |
|---|---|---|
| Introduction, 1–7 | Erhalten | [`docs/operations/goddess-reporting.md`](../operations/goddess-reporting.md), “Verifizierter Quellumfang” and “Daten- und Zustandsgrenzen”. |
| Fleet overview and G-series, 8–40 | Bewusst nicht als aktive Doku übernommen | B5 retains `src/the_hive/fleet_overview.py`, `src/the_hive/control_catalog.py`, `src/the_hive/server.py`, and focused tests, but these do not attest a fleet's current accounts, provider data, G-series membership, or a safe operator endpoint. [`README.md`](../../README.md), “Status and limitations”, retains the unknown-provider boundary; the base's fleet/credential-operational claims are not copied. |
| Reporter invariant, state/event storage, bounds, idempotence, 42–72 | Erhalten in boundary form; remaining detail bewusst nicht übernommen | [`docs/operations/goddess-reporting.md`](../operations/goddess-reporting.md), “Daten- und Zustandsgrenzen”, retains private bounded state, 744/512-KiB limits, leader lock, and invalid-event handling. The base's role-specific reporter-duty, exact event-buffer, and final-replacement procedure are not a complete authorized reporting interface and are deliberately not promoted to active instructions. |
| UTC buckets and backfill, 74–88 | Erhalten in boundary form; remaining detail bewusst nicht übernommen | [`docs/operations/goddess-reporting.md`](../operations/goddess-reporting.md), “Daten- und Zustandsgrenzen”, retains complete UTC-hour buckets and data-quality behavior; “Operative Grenze” explicitly withholds report generation. The base's due-time/backfill/finalization sequence would prescribe a state-writing reporting operation without current runtime evidence, so it is deliberately not copied. |
| CLI and timer commands, 89–124 | Erhalten in boundary form | [`docs/operations/goddess-reporting.md`](../operations/goddess-reporting.md), “Verifizierter Quellumfang” and “Operative Grenze”, uses current The-Hive unit names and says `run` mutates. Old wrapper and `systemctl` activation commands are unsafe/unverifiable legacy instructions. |
| Vault output, 125–138 | Erhalten in boundary form; remaining detail bewusst nicht übernommen | [`docs/operations/goddess-reporting.md`](../operations/goddess-reporting.md), “Daten- und Zustandsgrenzen” retains optional `CODEX_PROGRAMMING_VAULT` and its public-output caveat. The base's personal default location and writer procedure would expose a private deployment layout and prescribe state writes; they are deliberately excluded. |
| MCP tool matrix, 139–151 | Bewusst nicht als aktive Doku übernommen | Current source still declares `fleet_overview`, `fleet_status_compact`, and Goddess report tools, but the base combines those declarations with a mutating report-generation workflow. [`docs/operations/goddess-reporting.md`](../operations/goddess-reporting.md), “Verifizierter Quellumfang”, preserves the state-changing warning without a direct command recipe. |
| Open implementation stages, 153–162 | Bewusst nicht als aktive Dokumentation übernommen | This is a dated “open stages” claim. It has no current status validation and must not override [`ROADMAP.md`](../../ROADMAP.md)'s source-scoped current classifications. |

## `docs/operations/ci.md` in the base

| Base section / lines | Disposition | Current destination or precise reason |
|---|---|---|
| Identity and workflow-security assertions, 1–8 | Erhalten | [`docs/operations/ci.md`](../operations/ci.md), opening paragraph, and [`docs/development.md`](../development.md), “CI status boundary”. |
| Gate matrix and old manpage commands, 9–31 | Bewusst nicht als aktive Anleitung übernommen | The detailed reproduction commands reference legacy builder/manpage paths and a workflow whose manifest validation is currently contradictory. Current pages retain only focused source-backed checks and explicitly avoid a green-CI claim. |
| Deferred checks, coverage, Ruff, and remote-run commentary, 32–52 | Bewusst nicht als aktive Dokumentation übernommen | `telint` provenance, the stated Ruff baseline, optional local tools, and remote runner outcome were not revalidated as current operator guidance. [`docs/operations/ci.md`](../operations/ci.md), “Prüfgrenze”, supplies the safe limited scope. |
| External-source/license list, 53–73 | Bewusst nicht als aktive Produktdokumentation übernommen | The list is a dated external-reference appendix, not a current The-Hive product or operator contract; it does not establish a local or remote CI result. |

## `docs/operations/the-hive-home-broker.md` in the base

| Base section / lines | Disposition | Current destination or precise reason |
|---|---|---|
| Scope and hard boundary, 1–17 | Erhalten | [`docs/operations/the-hive-home-broker.md`](../operations/the-hive-home-broker.md), “Scope and hard boundary”. The current page additionally labels the legacy state-directory name as a compatibility identifier. |
| Artifact inventory, 19–36 | Erhalten | Same page, “Artifact inventory”. |
| Offline evidence checklist, 38–61 | Erhalten | Same page, “Offline evidence checklist”. |
| Systemd unit audit, 63–85 | Erhalten | Same page, “Systemd unit audit”. |
| SELinux static audit, 87–106 | Erhalten | Same page, “SELinux static audit”. |
| Release gate and handoff, 108–124 | Erhalten | Same page, “Release gate and handoff”. |

## `docs/security/hive-security.md` in the base

| Base section / lines | Disposition | Current destination or precise reason |
|---|---|---|
| Entire security boundary and review checklist, 1–24 | Erhalten | [`docs/security/hive-security.md`](../security/hive-security.md), all paragraphs. Terminology was updated to The Hive; the current page additionally records the source-backed unmaterialized Queen blocker. |

## `docs/security/selection-privacy.md` in the base

| Base section / lines | Disposition | Current destination or precise reason |
|---|---|---|
| Privacy/output/typed-normalizer boundary, 1–10 | Erhalten | [`docs/security/selection-privacy.md`](../security/selection-privacy.md), first two paragraphs. |
| Private-data handling and old API-token path, 12–15 | Erhalten with deliberate path removal | [`docs/security/selection-privacy.md`](../security/selection-privacy.md), third paragraph, preserves the prohibition while deliberately not publishing the historical private token-file path. |
| Stale-usage and passive-anchor boundary, 17–19 | Erhalten | [`docs/security/selection-privacy.md`](../security/selection-privacy.md), final paragraph. |

## Closure

Every reduced source section above now has a final disposition: it is retained
in a named current section, retained only as an explicit safety boundary, or is
deliberately not part of active D136 documentation for the stated
unsafe/unverifiable-legacy reason. The Resource-Monitor exception is preserved
separately in [`docs/operations/resource-monitor.md`](../operations/resource-monitor.md).
No removed material relies on Git history alone for its disposition.

No current page may turn former checkout commands, private local paths,
provider claims, desktop state, unit activation, or remote status into a live
assertion.
