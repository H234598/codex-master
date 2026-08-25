---
name: codex-master-fleet
description: Use when coordinating codex-master Masterjet work as a Queen or Teamleiterin, delegating Bienen, attesting fleet state, or handling assignment-bound reports.
metadata:
  short-description: Route Queen and TL Masterjet coordination safely
---

# Codex Master Fleet

Dieser Skill ist der kurze kanonische Repositoryrouter für Queen und
Teamleiterin. Er ist keine zweite Hive-Policy-Wahrheit und kein Worker-Skill.

## Autoritätsgrenze

Autorität kommt in dieser Reihenfolge aus Common Policy und kanonischen
Masterjet-Teilplänen, materialisierter Rolle/Klasse, Principal, Lease und
Scope, dann aus der aktuell attestierten Masterjet-/MCP-Generation.
Die aktuell attestierte Masterjet-/MCP-Generation ist für volatile Auswahl
allein maßgeblich.
Repositorycode ist Ist-Evidenz, nie Policy. Fehlende oder widersprüchliche
Attestation bedeutet fail-closed: keine Auswahl, kein Spawn, kein Retry.

Keine statische Modell-, Provider-, Klassen-, Preis-, Limit- oder Toolliste
pflegen. Volatile Auswahl entsteht nur aus der attestierten Generation und
ihren Capability-, Auth-/Quota-, Kosten- und Ressourcengates.

Workerinnen erhalten diesen Leitungsskill nicht. Ihre Klasse materialisiert
nur die für Assignment und Scope nötigen Regeln und Werkzeuge.

## Rolle bestimmen und routen

1. Rolle, Auftrag, `repo_id`, Principal, Lease, Scope und Lifecycle ermitteln.
2. Immer [gemeinsame Invarianten](references/common-invariants.md) lesen.
3. Queen liest genau eine Rollenreferenz:
   [Queen-Bedienung](references/queen-operations.md).
4. Teamleiterin liest genau eine Rollenreferenz:
   [TL- und Workerführung](references/tl-worker-operations.md).
5. Bei Diagnose, Refresh, Retry, Bericht oder Topicresume zusätzlich
   [Diagnose und Wiederaufnahme](references/diagnostics-retry-reporting.md)
   laden.

Nur Queen und Teamleiterin erreichen diesen Router. Eine Workerin fragt bei
falscher Materialisierung ihre Parent-TL; sie lädt keine Leitungsreferenz.

## Sicherer Standardablauf

1. Auftrag bounded sammeln; Security-, Scope- und Datenverlustblocker sofort
   melden.
2. Aktuelle Generation vor Auswahl und vor jedem Spawn-Retry attestieren.
3. Angebotene Rolle-/Lifecycle-/Capability-Kombination gegen Lease und Scope
   prüfen; kein nicht attestiertes Ersatzmodell oder Legacyfallback.
4. Entscheidung, Blocker, Handoff und Risiko über den typisierten zuständigen
   Kommunikationspfad berichten.
5. Nach kohärentem Slice gezielt testen und getrennte Review- und
   Integrationsrollen übergeben.

Die Referenzen werden nur für die jeweilige Rolle oder Diagnose geladen.
