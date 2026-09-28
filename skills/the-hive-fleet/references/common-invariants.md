# Gemeinsame Fleet-Invarianten

## Autorität und Attestation

Common Policy und kanonische Masterjet-Teilpläne bestimmen Sollregeln.
Materialisierte Rolle/Klasse, Principal, Lease und Scope begrenzen jede
Aktion. Die aktuell attestierte Generation liefert volatile Klassen, Provider,
Modelle, Reasoning, Tools, Kosten, Ressourcen und Quota. Repositorycode ist
nur Ist-Evidenz.
Jede Aktion bleibt an materialisierter Rolle/Klasse, Principal, Lease und
Scope gebunden.

Queen und TL attestieren Masterjet, MCP, Plugin, Manifest, Approval und Cache
spätestens stündlich sowie vor jedem Spawn-Retry. Fehlende, widersprüchliche
oder abgelaufene Evidenz ist ein fail-closed Blocker.

## Runtime-Migrationsvertrag

Die [Runtime-Migrationspolicy v1](../../../src/the_hive/markdown/runtime-migration-policy-v1.json)
ist die alleinige verbindliche Quelle für Runtime- und
Installationsmigrationen. Der Fleet-Skill und sein MCP-Koordinationspfad
sammeln nur read-only Evidenz und erteilen keine Live-Autorität: kein Install,
kein Activate, kein Reload und kein Cutover. Vor bekannter Root Cause darf nur
reviewte, begrenzte und secretfreie Telemetrie als nicht autoritative Evidenz
integriert werden, wird aber nie zur zweiten Autorität und eröffnet kein
Aktivierungsgate. Diagnose, reviewed Remediation und Aktivierung bleiben
getrennte Gates; Installieren,
Aktivieren, Beobachten und endgültiges Committen bleiben getrennte Phasen.
Der Vertrag fordert einen gebundenen deterministischen Dry-run, CAS/Fencing,
ein redigiertes Transaktionsjournal mit Rollback oder HOLD sowie secret-freie,
begrenzte Telemetrie. Eine grüne interne Probe genügt nicht; die Evidenz
enthält mindestens einen echten Consumer-E2E-Vertrag.

Vor jeder Generierung oder Mutation prüft eine attestierte
Kompatibilitätsmatrix Manager-, Runtime- und Client-Versionen sowie
unterstützte Eigenschaften. Evidenz hat eine definierte Freshness/TTL;
fehlende, widersprüchliche oder veraltete Liveevidenz ist fail-closed und kann
keinen Cutover öffnen. Die redaktierte Real-Live-Fixture ist Pflicht vor
Aktivierung oder Cutover, nicht vor Policy- oder Diagnoseintegration. Damit
ist ihr Fehlen ein Aktivierungsblocker, aber kein Zirkelschluss gegen die
Integration der Policy oder Diagnostik, welche die Fixture erst ermöglicht.

Der Fehlerklassifikator ist ein versionierter geschlossener Vertrag. Vor Live
belegt eine Negativmatrix jede unterstützte Fehlerfamilie; unbekannt bleibt
fail-closed. Ein Canary durchläuft Manager-Syntax/Transport, dann
Namespace/Sandbox, dann Helper und zuletzt Produktlogik. Die früheste rote
Schicht beendet den Lauf. Höchstens ein Live- oder Canary-Versuch ist je
evidenzveränderndem, reviewtem Commit zulässig. Zwei trotz verbesserter
Klassifikation generische oder blind gebliebene Ergebnisse führen zu `HOLD`
und nativer Plattformdiagnostik oder expliziter Userentscheidung, nicht zu
weiterem Runtimearchitektur-Ausbau. Der Canary darf kanonische Artefakte nicht
mutieren. Nach zwei blind gebliebenen Diagnoserevisionen ist `HOLD`
verbindlich; eine dritte Klassifikationsarchitektur ist verboten.

Vor jeder Mutation wird eine immutable, redigierte Pre-Baseline erhoben;
Post-Baseline und Quieszenz sind Teil des Ergebnisses. Ohne Pre-Baseline gibt
es keine Unverändertheitsbehauptung. Das Cleanup-Ergebnis hat Vorrang vor
Primärdiagnose. Cleanup prüft Ownership unmittelbar vor jeder Mutation und
fasst Foreign Objects nie an. Das Diagnoseharness hat ein
Scope-/Komplexitätsbudget für Dateien, Produktions-LOC, Fehlerklassen und
Liveversuche. Seine Überschreitung verlangt ein Designreview und eine
einfachere native Alternative. Ein vollständiger Runtimeumbau erfordert eine
begründete Notwendigkeit gegenüber einem lokalen getesteten Minimalfix. Schließt
der Minimalfix die Root Cause, ist er vorzuziehen.

Kompatibilität ist ausschließlich der genau benannte, attestierte
Vorgängerversion-Input der Policy. Ein ungebundener Legacy-,
Kompatibilitäts- oder Fallback-Laufzeitpfad bleibt gesperrt.

## Admission und Kommunikation

Keine numerische globale, Serien- oder Provider-Flottenobergrenze. Admission
nutzt aktuell attestierte Ressourcen-, Capability-, Auth-/Quota-, Kosten- und
Ruckel-Gates. Operator-Batchgrenzen messen keine laufende Concurrency.

Nach Bus-Cutover laufen Entscheidungen, Blocker, Handoffs und Risiken über
typisierte Kommunikationspfade. Keine Rolle erweitert Scope oder ersetzt
attestierte Auswahl durch Repository- oder Homewissen.

Kein Übergangspfad, wenn sauberer Neubau oder Cutover möglich ist.
