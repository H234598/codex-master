---
name: the-hive-fleet
description: Use when coordinating The Hive Masterjet work as a Queen or Teamleiterin, delegating Bienen, attesting fleet state, or handling assignment-bound reports.
metadata:
  short-description: Route Queen and TL Masterjet coordination safely
---

# The Hive Fleet

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

## Runtime-Migrationspolicy

Die verbindliche Quelle für eine Runtime- oder Installationsmigration ist die
[Runtime-Migrationspolicy v1](../../src/the_hive/markdown/runtime-migration-policy-v1.json).
Dieser Skill und sein MCP-Koordinationspfad sind ausschließlich
evidenzbasiert und read-only: Sie sammeln und berichten Attestierungen,
Preflight- und Testevidenz, erteilen aber keine Live-Autorität. Vor belegter
Root Cause darf nur reviewte, begrenzte und secretfreie Telemetrie als nicht
autoritative Evidenz integriert werden; sie ist keine zweite Autorität und
öffnet kein Produktaktivierungsgate. Sie
dürfen weder Install noch Activate noch Reload noch Cutover ausführen oder
erlauben.

Diagnosegate, reviewed Remediationgate und Aktivierungsgate sind getrennt.
Die Policy- oder Diagnoseintegration bleibt ohne Real-Live-Fixture zulässig;
vor Aktivierung oder Cutover ist die redaktierte Real-Live-Fixture dagegen
Pflicht. Installieren, Aktivieren, Beobachten und endgültiges Committen sind
getrennte Phasen mit je eigenem Gate. Vor jeder Generierung oder Mutation
muss eine attestierte Kompatibilitätsmatrix von Manager-, Runtime- und
Client-Versionen sowie unterstützten Eigenschaften vorliegen. Fehlende,
veraltete oder widersprüchliche Evidenz bleibt fail-closed.

Ein Live- oder Canary-Versuch ist höchstens einmal je evidenzveränderndem,
reviewtem Commit zulässig; blinde Wiederholung ist verboten. Zwei trotz
verbesserter Klassifikation generische oder blind gebliebene Ergebnisse
erzwingen `HOLD`, native Plattformdiagnostik oder eine explizite
Userentscheidung statt weiterer Runtimearchitektur. Der versionierte,
geschlossene Fehlerklassifikator muss vor Live mit einer Negativmatrix für
jede unterstützte Fehlerfamilie belegt sein; unbekannte Fehler bleiben
fail-closed. Canary-Diagnose läuft schichtweise von Manager-Syntax/Transport
über Namespace/Sandbox und Helper zur Produktlogik; die früheste rote Schicht
beendet den Lauf und darf kanonische Artefakte nicht mutieren. Nach zwei blind
gebliebenen Diagnoserevisionen ist `HOLD` verbindlich; eine dritte
Klassifikationsarchitektur ist verboten.

Eine Vorbaseline ist vor jeder Mutation immutable und redigiert zu erheben;
Post-Baseline und Quieszenz gehören zum Ergebnis. Das Cleanup-Ergebnis hat
Vorrang vor Primärdiagnose; Cleanup prüft Ownership unmittelbar vor jeder
Mutation und fasst Foreign Objects nie an. Das
Diagnoseharness hat ein Budget für Dateien, Produktions-LOC, Fehlerklassen
und Liveversuche; eine Überschreitung verlangt Designreview und eine
einfachere native Alternative. Ein Runtimeumbau braucht gegenüber einem
lokalen getesteten Minimalfix eine begründete Notwendigkeit; schließt der
Minimalfix die Root Cause, ist er vorzuziehen.
Kompatibilität ist nur für die in der Policy genau benannte und attestierte
Vorgängerversion als explizit gebundener Input zulässig; es gibt keinen
impliziten Legacy-, Kompatibilitäts- oder Fallback-Laufzeitpfad.

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
2. Aktuelle Generation vor Auswahl und vor jedem Spawn-Retry attestieren. Bei
   Runtime- oder Installationsarbeit gehört ein Read-only-Live-Preflight vor
   Entwicklung und nochmals vor einem angefragten Cutover zur Evidenz.
3. Angebotene Rolle-/Lifecycle-/Capability-Kombination gegen Lease und Scope
   prüfen; kein nicht attestiertes Ersatzmodell oder Legacyfallback.
4. Entscheidung, Blocker, Handoff und Risiko über den typisierten zuständigen
   Kommunikationspfad berichten.
5. Nach kohärentem Slice gezielt testen und getrennte Review- und
   Integrationsrollen übergeben.

Die Referenzen werden nur für die jeweilige Rolle oder Diagnose geladen.
