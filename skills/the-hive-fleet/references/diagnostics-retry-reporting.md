# Diagnose, Retry und Bericht

## Refresh und Retry

Queen oder TL attestiert spätestens stündlich und vor jedem Spawn-Retry
Masterjet, MCP, Plugin, Manifest, Approval und Cache. Fehlt Spawn ohne eigene
aktive Biene, zuerst Refresh ausführen, dann schlafend und tokensparend mit
5, 5, 5, 10, 15, 20, 40, 60, 90, 120, 150, 180, 240, 300 Minuten retryen;
danach bleiben Intervalle bei 300 Minuten. Kein Busy-Polling und kein
Legacyfallback.

Laufzeit, Schweigen oder ein langer Test sind kein Grund zum Abbruch.
Abbruch nur bei konkreter begründeter Fehlerannahme.

## Runtime-Migrationsdiagnose

Die [Runtime-Migrationspolicy v1](../../../src/the_hive/markdown/runtime-migration-policy-v1.json)
gilt auch für Diagnoseberichte. Der Fleet-Skill und MCP-Koordinationspfad
erheben nur read-only, redigierte Evidenz; sie führen weder Install noch
Activate noch Reload noch Cutover aus oder erlauben dies. Ein Bericht bindet
Dry-run-Inputs und -Digests, Transaktions-ID/Fence, Phase, Fehlerklasse,
Rollback- oder HOLD-Zustand und finale Identität, ohne Secrets oder
unbegrenzte Felder aufzunehmen. Zwei identische Live-Fehlschläge sperren den
dritten Versuch bis neue Ursachenevidenz und ein Regressionstest vorliegen.

Diagnostik-, Remediation- und Aktivierungsautorität bleiben getrennt.
Vor bekannter Root Cause darf nur reviewte, begrenzte und secretfreie
Telemetrie als nicht autoritative Evidenz integriert werden, ist aber nie eine
zweite Autorität und darf keine Produktaktivierung öffnen. Vor jedem Live-
oder Canary-Versuch bindet der Bericht neue, reviewte Evidenz an genau einen
Commit; blinde Wiederholung ist verboten.
Nach zwei trotz verbesserter Klassifikation generischen oder blind gebliebenen
Ergebnissen ist `HOLD` zu berichten und native Plattformdiagnostik oder eine
explizite Userentscheidung zu verlangen statt das Runtimeharness weiter
auszubauen.

Der Fehlerklassifikator ist versioniert und geschlossen. Vor Live weist eine
Negativmatrix jede unterstützte Fehlerfamilie nach; unbekannt bleibt
fail-closed. Die Canary-Reihenfolge ist Manager-Syntax/Transport,
Namespace/Sandbox, Helper und Produktlogik; die früheste rote Schicht beendet
den Lauf und darf kanonische Artefakte nicht mutieren. Nach zwei blind
gebliebenen Diagnoserevisionen ist `HOLD` zu berichten; eine dritte
Klassifikationsarchitektur ist verboten. Vor jeder Mutation wird eine
immutable, redigierte Pre-Baseline erhoben. Der Bericht enthält auch
Post-Baseline und Quieszenz; ohne Pre-Baseline behauptet er keine
Unverändertheit. Das Cleanup-Ergebnis hat Vorrang vor Primärdiagnose. Cleanup
berichtet die frisch geprüfte Ownership; Foreign Objects bleiben unberührt.
Evidenz-Freshness/TTL ist auszuweisen, damit veraltete Evidenz kein Gate
öffnet.

Die Real-Live-Fixture ist vor Aktivierung oder Cutover Pflicht, nicht vor
Policy- oder Diagnoseintegration. Installieren, Aktivieren, Beobachten und
endgültiges Committen bleiben getrennte Phasen. Vor Generierung oder Mutation
gehört eine attestierte Kompatibilitätsmatrix von Manager-, Runtime- und
Client-Versionen sowie unterstützten Eigenschaften zur Evidenz. Das
Diagnoseharness berichtet sein Scope-/Komplexitätsbudget für Dateien,
Produktions-LOC, Fehlerklassen und Liveversuche; eine Überschreitung verlangt
Designreview und eine einfachere native Alternative. Ein vollständiger
Runtimeumbau ist gegenüber einem lokalen getesteten Minimalfix zu begründen;
schließt dieser die Root Cause, ist er vorzuziehen.

## Enge Berichtsausnahme und Resume

`agent_assignment_report` ist nur nach `agent_wait` oder
`agent_report_request` mit bekannter Assignment-ID zulässig. Der Ausschnitt
bleibt assignmentgebunden, zeichen- und zeilenbegrenzt, ANSI-bereinigt und
redigiert; er ist kein freier Terminal- oder Rohlogzugriff.

Berichte sind kurz und enthalten Ergebnis, Evidenz, offene Risiken und
nächsten zuständigen Schritt. Bei Wiederaufnahme erst vorhandene passende
Session und Topicbindung prüfen; nur bei fehlendem Resume eine neue Biene
anfragen.
