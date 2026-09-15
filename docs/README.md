# The Hive documentation

This is the normal, versioned repository documentation navigation for The
Hive. It deliberately separates product and operator material from plans,
templates, and handoffs. It does not use Wiki navigation.

## Start here

- [Repository overview](../README.md): scope, installation boundary, basic
  configuration, operation, and trust-boundary summary.
- [Roadmap](../ROADMAP.md): source-integrated work, prepared work, blockers,
  and later work.

## Core product and operator documentation

- [Architecture](architecture.md) — component boundaries and data flow.
- [Control plane](control-plane.md) — typed Hive coordination, authority,
  admissions, and queues.
- [Resolver](resolver.md) — class, capability, model, and selection
  resolution.
- [Installation](installation.md) — attested runtime-image and installation
  boundary.
- [Configuration](configuration.md) — versioned inputs, schemas, and change
  boundary.
- [Operations runbook](operations/runbook.md) — evidence-first operating
  sequence and mutation boundary.
- [Recovery](operations/recovery.md) — bounded local reconciliation boundary.
- [Troubleshooting](operations/troubleshooting.md) — safe evidence gathering
  and escalation.
- [Security and trust boundaries](security/hive-security.md) — principal,
  scope, grant, state, and output-boundary guidance.
- [Selection privacy](security/selection-privacy.md) — account-aware selection
  privacy material.
- [Development and focused checks](development.md) — source-backed focused
  checks and the CI-status boundary.
- [Releases](releases.md) — manifest-attested runtime-image release boundary.
- [Changelog](../CHANGELOG.md) — recorded changes, not runtime-installation
  evidence.
- [Consolidation record](migration/wiki-consolidation.md) — preservation and
  classification record for former versioned Wiki sources; it is historical
  documentation, not an operational instruction.

## Specialist documentation

- [Agent pool](agent-pool.md)
- [Account-aware selection](account-aware-selection.md)
- [Authentication-copy boundary](auth-copy.md)
- [Hive operations](operations/hive-operations.md)
- [Selection operations](operations/selection-operations.md)
- [Pilot provisioner](operations/hive-pilot-provisioner.md)
- [Home-broker boundary](operations/the-hive-home-broker.md)
- [Goddess reporting](operations/goddess-reporting.md)
- [Resource monitor (H4)](operations/resource-monitor.md) — optional
  resource-evidence service and lifecycle boundary.
- [Notification language usage](operations/notification-language-uses.md)
- [Selection migration](migration/hive-selection-migration.md)

## Work material, not active product navigation

The following retained material is useful for history or ongoing work but is
not an operator source of truth: `plans/`, `superpowers/plans/`,
`superpowers/specs/`, [external-plan-handoff.md](operations/external-plan-handoff.md),
and [copilot-review-templates.md](copilot-review-templates.md). Consult it
only with its date, scope, and status in mind; it does not make a feature live.
