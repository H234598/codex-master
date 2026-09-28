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

## Enge Berichtsausnahme und Resume

`agent_assignment_report` ist nur nach `agent_wait` oder
`agent_report_request` mit bekannter Assignment-ID zulässig. Der Ausschnitt
bleibt assignmentgebunden, zeichen- und zeilenbegrenzt, ANSI-bereinigt und
redigiert; er ist kein freier Terminal- oder Rohlogzugriff.

Berichte sind kurz und enthalten Ergebnis, Evidenz, offene Risiken und
nächsten zuständigen Schritt. Bei Wiederaufnahme erst vorhandene passende
Session und Topicbindung prüfen; nur bei fehlendem Resume eine neue Biene
anfragen.
