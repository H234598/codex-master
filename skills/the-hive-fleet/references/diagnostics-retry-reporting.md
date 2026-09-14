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

## Enge Berichtsausnahme und Resume

`agent_assignment_report` ist nur nach `agent_wait` oder
`agent_report_request` mit bekannter Assignment-ID zulässig. Der Ausschnitt
bleibt assignmentgebunden, zeichen- und zeilenbegrenzt, ANSI-bereinigt und
redigiert; er ist kein freier Terminal- oder Rohlogzugriff.

Berichte sind kurz und enthalten Ergebnis, Evidenz, offene Risiken und
nächsten zuständigen Schritt. Bei Wiederaufnahme erst vorhandene passende
Session und Topicbindung prüfen; nur bei fehlendem Resume eine neue Biene
anfragen.
