# Diagnose- und Reparaturplan: Notfall-Delta, TE-AW und serielle Notfall-Queen

Status: abgeschlossen (2026-08-19); produktiver Queen-Start bleibt bis zum Hive-Enablement bewusst fail-closed

## Aktueller Ist-Zustand und offene Lücke

Ein Teil der Anzeige- und Limittracker-Grundlage ist bereits vorhanden: Der
Notfallzustand kann derzeit als reversibles Overlay geschrieben werden, TE-
Ausgangswerte werden im Sanitizer typgesichert behandelt, und Spark-Limits
werden getrennt vom normalen Pool betrachtet. Die erste Anzeige-Root-Cause
ist inzwischen behoben: Gleichzeitige Abfragen desselben Pools mit
unterschiedlichen Fenstern ersetzen nur noch identische Fenster und löschen
nicht mehr den gesamten Pool. Die End-to-End-Schaltermatrix ist erweitert und
grün. Für die Queen existiert nun eine generationsgebundene, dateigesperrte
Zustandsmaschine und eine echte Anbindung an die vorhandene `agent_start`-
Primitive. Die aktuell materialisierten q-Homes tragen zwar das
Teamleiterinnen-Profil, aber weder Provider noch Serie sind eine dauerhafte
Klassenbindung. Der Klassenkatalog definiert
Königinnen bewusst als logische, persistente Hive-Principals mit
`home_policy: none` und `session_policy: logical`; dies bezeichnet kein
dauerhaftes Serienhome, nicht den Verzicht auf ein Runtime-Home. Als neue
verbindliche Ergänzung erhält jede gestartete Queen ein temporäres,
leasegebundenes Home unter `/home/teladi/.codex-agents/Queens/Queen<N>`.
Die Hive-Königin
`queen-codex-master` ist allerdings noch nicht materialisiert und der Hive ist
derzeit deaktiviert. Deshalb wird bewusst
`queen_spawn_unavailable:hive_queen_runtime_not_materialized` persistiert,
statt einen nativen Spawn zu fingieren. Der produktive Queen-Start bleibt
bewusst blockiert, bis der geplante logische Runtimeadapter zusammen mit einem
materialisierten Hive-Principal veröffentlicht ist. Dies ist ein expliziter,
maschinenlesbarer Betriebsgrenzwert und keine unerkannte Restarbeit.

## Festgehaltene Anforderungen

1. Ein Notfall-Delta darf die normalen Codex-Usage-Einstellungen nicht
   überschreiben. Nach Ende des Notfalls müssen exakt die vorherigen Werte
   gelten. War Delta vorher aus, ist es danach wieder aus.
2. Im Notfall gilt für die Anzeige das vorhandene Fenster in der Reihenfolge
   `5h`, sonst `Woche`, sonst `30 Tage`.
3. `Setze eigenen AW` muss in der Tokenverbrauchs- und Tokenende-Tabelle
   unabhängig voneinander funktionieren. Ein aktivierter AW darf weder Delta,
   Tokenende noch Coverage ausblenden.
4. Eine Notfall-Queen arbeitet Plan für Plan. Solange der Notfall aktiv ist,
   wird nach vollständigem Abschluss der nächste freigegebene Plan gewählt.
   Es darf niemals eine zweite Notfall-Queen entstehen.
5. Wird der Notfall beendet, beendet die Queen nach dem aktuellen vollständig
   abgearbeiteten Plan sich und ihre Kinder graceful. Dösende Gottbienen,
   Königinnen und Teamleiterinnen zählen nicht als arbeitende Workerinnen.

## Befund aus dem Screenshot

- BW_Work hat in der Verbrauchstabelle `Setze eigenen AW` und in der
  Tokenendetabelle ebenfalls `Setze eigenen AW` aktiviert.
- Die Tabellen zeigen scheinbar keine berechneten Werte. Das ist kein reines
  Formatproblem; zunächst muss unterschieden werden, ob der Wert bereits im
  Backend-DTO fehlt, beim Sanitizing verloren geht, bei der Fensterselektion
  herausfällt, durch Zielrouting verborgen wird oder nur durch die Oberfläche
  nicht neu gezeichnet wird.
- Die bisherige Matrix war zu renderer-nah. Sie testete synthetische
  `cost_windows` teilweise direkt und konnte dadurch Fehler zwischen
  Payload-Validierung, Sanitizing, Normalisierung, Fensterselektion und
  Rendering nicht erkennen.

## Diagnoseplan

### 1. Reproduzierbaren Zustand einfrieren

- Für einen Testaccount jeweils einen frischen Snapshot mit gültigem 5h-,
  Wochen- und Monatsfenster erzeugen.
- Für Tokenverbrauch und Tokenende je einen DTO-Datensatz mit
  `consumed_percentage_points`, `estimated_seconds_to_exhaustion`,
  `baseline_used_percent`, `coverage` und `sample_count` sichern.
- Vor jeder Testgruppe Settings, Snapshot-Generation, Applet-Generation und
  Emergency-Override-Datei protokollieren.
- Keine echte Usage-Abfrage und keine echte Agentenmutation in den
  Kombinationstests verwenden.

### 2. Vollständigen Datenpfad instrumentieren

Für jeden Testfall müssen Zwischenwerte beobachtbar sein, ohne geheime Daten
zu loggen:

```text
Backend-DTO
  -> _validatePayload
  -> _safeConsumptionWindows
  -> _normalizeConsumptionRow / _normalizeForecastRow
  -> _selectConsumptionWindows
  -> _consumptionWindowPart / _forecastWindowPart
  -> _elementTargetEnabled
  -> panel / hover / click
```

Für jede Stufe werden nur folgende Fakten ausgegeben: Account, Pool, Fenster,
Wert vorhanden ja/nein, AW vorhanden ja/nein, Coverage, Sichtbarkeit,
Normalisierungsfehler und Generation.

### 3. TE-AW separat beweisen

- Prüfen, dass `forecast-baseline-enabled` und
  `forecast-baseline-minutes` aus der Tokenendetabelle tatsächlich in den
  kombinierten Verbrauchszeilen landen.
- Prüfen, dass der Backend-Auftrag bei abweichendem TE-AW eine getrennte
  Berechnung anfordert.
- Prüfen, dass die Antwort für das TE-Fenster `baseline_used_percent`
  enthält.
- Prüfen, dass der Sanitizer das Feld als endliche Zahl zwischen 0 und 100
  erhält und `null` nicht zu `0` coerct.
- Prüfen, dass TE-AW in `compact`, `compact-minutes`, `verbose` und
  `custom` sichtbar bleibt.
- Prüfen, dass eine fehlende AW-Messung nur den AW-Text auslässt, niemals die
  komplette TE-Zeile.

### 4. Schalter- und Zielmatrix neu aufbauen

Nicht nur 5 Schalter × 4 Tabellen testen, sondern pro Tabelle alle folgenden
Dimensionen kombinieren:

- `show-panel`: aus/an
- `show-tooltip`: aus/an
- `hide-when-zero`: aus/an, mit Wert 0 und Wert > 0
- `coverage`: aus/an, für `complete`, `partial`, `stale`, `insufficient`
- `Setze eigenen AW`: aus/an, mit gültigem, fehlendem und ungültigem AW
- Zielrouting: Leiste/Hover/Klick unabhängig aus/an
- Format: kompakt, Dezimal-TE, Stunden/Minuten-TE, ausführlich,
  benutzerdefiniert
- Fenster: 5h, Woche, 30 Tage, Spark
- Delta global: aus/an
- Emergency-Override: fehlt, aktiv, beendet

Jede Kombination muss eine strukturierte Erwartung prüfen:

```text
gültiger Wert + Ziel aktiv       => Zeile sichtbar
gültiger Wert + Ziel aus         => nur dieses Ziel unsichtbar
AW aktiv + AW vorhanden          => AW sichtbar
AW aktiv + AW nicht vorhanden    => AW fehlt, Hauptwert bleibt sichtbar
Coverage aus                     => nur Coverage-Marker fehlt
Override beendet                 => exakte vorherige Settings sichtbar
```

Zusätzlich wird jede relevante Kombination einmal über den echten Pfad
`_validatePayload -> _safeConsumptionWindows` ausgeführt. Direkte Renderer-
Fixtures gelten nur noch als ergänzende Unit-Tests.

### 5. „Alles leer“-Fehler isolieren

- Vor und nach jedem Settings-Callback prüfen, ob `_consumptionSettings`,
  `_forecastSettings`, `_styleTargets` und `_usages` noch dieselbe Generation
  besitzen.
- Prüfen, ob ein fehlerhaftes TE-Format die gesamte Zeile auf `null` setzt.
- Prüfen, ob ein fehlendes `forecast-limit-window` auf das TV-Fenster fällt,
  obwohl das TE-Fenster separat gespeichert wurde.
- Prüfen, ob `_elementTargetEnabled` bei fehlendem Target mit einem falschen
  Legacywert auf `false` fällt.
- Prüfen, ob ein Emergency-Override beim Beenden eine leere, aber gültige
  Settingszeile erzeugt.
- Prüfen, ob Reload/Migration die vier Tabellen nacheinander speichert und
  die jeweils vorherige Tabelle dabei überschreibt.
- Prüfen, ob ein Applet-Reload die Anzeige vor dem Backend-Refresh leer malt
  und keine letzte gültige Anzeige behält.

### 6. Notfall-Delta rückstandsfrei machen

- Override-Datei nur als Overlay behandeln; niemals die Cinnamon-Settings
  mutieren.
- Beim Aktivieren einen Fingerprint der betroffenen normalen Zeile und des
  globalen Delta-Schalters speichern.
- Beim Deaktivieren Overlay atomar entfernen und die normale Zeile erneut aus
  Cinnamon laden.
- Bei Crash/Neustart einen abgelaufenen Override anhand von `until` oder
  fehlendem aktiven Fast-/Spark-Zustand entfernen.
- Regression: Delta vorher aus, Notfall an, Notfall aus => Delta aus.

### 7. Notfall-Queen als idempotente Zustandsmaschine

Zustände:

```text
idle
 -> requested
 -> running(plan_id)
 -> finishing(plan_id)
 -> next(plan_id)
 -> draining
 -> idle
```

- Ein exklusiver Lease mit Generation verhindert zwei Notfall-Queens.
- Der aktuelle Plan und die Kinder werden persistiert.
- Während `running` oder `finishing` darf keine neue Queen gestartet werden.
- Bei aktivem Notfall: nach `completed` den nächsten freigegebenen Plan
  zufällig aus der begrenzten Kandidatenliste wählen.
- Bei beendetem Notfall: keinen neuen Plan starten; aktuellen Plan sauber
  beenden und danach Kinder und Queen graceful schließen.
- Bei Crash: Lease prüfen, Wiedereinstiegspunkt laden, niemals doppelt starten.
- Nur Pläne mit expliziter Freigabe bzw. zulässigem `in Umsetzung`-Status
  kommen in die Kandidatenliste.

Implementiert sind außerdem:

- `emergency-queen-state.json` mit Generation, aktuellem Plan, Queue,
  Queen-Agent und Blockergrund
- ein exklusiver Dateilease für konkurrierende MCP-Prozesse
- `emergency_queen_status` und `emergency_queen_plan_completed` als MCP-
  Übergabepunkte
- Kinder werden generationsgebunden registriert und abgemeldet; der
  Draining-Reaper wartet auf Queen und Kinder gleichermaßen.
- Nach einem Abschluss wird der nächste Plan an dieselbe Queen signalisiert;
  bei beendetem Notfall wird `draining` gesetzt und erst nach dem Ende der
  verwalteten Session auf `idle` zurückgesetzt.
- die derzeitigen q-Homes werden nicht stillschweigend als Queen-Ziele
  verwendet; ihre momentane Teamleiterinnen-Profilierung ist keine
  Provider- oder Serienregel
- Queens besitzen kein dauerhaftes Serienhome. Ihre gestartete Runtime erhält
  dagegen ein temporäres, atomar materialisiertes `Queen<N>`-Home; ein
  expliziter Blocker gilt, solange dieser Runtimeadapter nicht materialisiert
  ist

### 7a. Queen-Runtime-Home (verbindliche Ergänzung vom 2026-08-19)

- Lokaler Root bis zur Control-VM:
  `/home/teladi/.codex-agents/Queens/`.
- Pro erfolgreichem Queen-Spawn erzeugt der Materializer genau ein neues,
  monoton nummeriertes `Queen<N>` mit privaten Rechten. Es enthält nur
  Runtime-Dateien: isoliertes `CODEX_HOME`, Wrapper, die passenden
  Klassen-Markdowns und Skills sowie kurzlebige, leasegebundene
  Credential-Referenzen.
- Principal-ID, Repository, Lease, Fence und Runtime-Generation werden vor
  dem Start atomar an das Home gebunden und beim Resume erneut validiert.
- Beim graceful Ende wird das Runtime-Home abgebaut. Bei Crash oder
  unsicherem Cleanup bleibt es quarantänisiert, bis der Reaper die Bindung
  geprüft hat; es wird weder wiederverwendet noch als Erfolg verbucht.
- Persistente Queen-Daten — Identität, Repository-Memory, Queue, Authority,
  Audit und ResumeCapsule — liegen außerhalb des Homes in der Control Plane.
- Auf der späteren Control-VM wandert nur der Root auf den ausgewählten
  Execution Node; der Materialisierungs-, Fencing- und Abbauvertrag bleibt
  identisch.

Erster Implementierungsslice:

- `src/codex_master/queen_runtime.py` enthält jetzt den isolierten
  `QueenRuntimeHomeManager`. Er allokiert nur monoton neue `Queen<N>`-Homes,
  persistiert die Zuteilung vor der Materialisierung, erstellt ein privates
  `codex-home` und bindet ein redigiertes Metadatenobjekt an Principal,
  Repository, Lease, Fence und Generation.
- Der Reaper entfernt ausschließlich Homes mit exakt passender, aktiver
  Bindung. Fehlende oder manipulierte Metadaten sowie Cleanupfehler werden
  quarantänisiert. Nummern werden auch nach einem erfolgreichen Abbau nie
  wiederverwendet.
- Die Fabrik startet noch keine Königin: Der Hive ist weiterhin deaktiviert
  und der produktive Runtimeadapter muss die Factory erst an die kanonische
  Principal-/Lease-/Providerkette anschließen.

## Akzeptanzkriterien

- TE-AW kann in jeder gültigen TE-Format-/Ziel-/Coverage-Kombination sichtbar
  geschaltet werden.
- Keine Kombination löscht mehr Delta, TE oder Coverage der jeweils anderen
  Tabelle.
- Die komplette Matrix läuft durch den echten Sanitizer- und
  Normalisierungspfad.
- Emergency-Delta kehrt nach Ende exakt zum vorherigen Zustand zurück.
- Spark-Limitdruck startet keine Fast-Mode-Aktion.
- Es existiert höchstens eine Notfall-Queen; es werden keine neuen Queens
  gestartet, solange die bestehende Queen oder ihre Kinder noch einen Plan
  abschließen.
- Alle Zustandsübergänge sind reload- und resume-fähig und dokumentiert.

## Aktuelle Nachweise

- codex-usage Applet: 309/309 JavaScript-Tests bestanden
- Queen-/Limittracker-/Runtime-Fokus: 9/9 Python-Tests bestanden
- Python-Syntaxprüfung für `server.py`, `limit_tracker.py` und
  `control_catalog.py` bestanden
- Same-Pool-Refresh mit Verbrauch `5h` und Tokenende `Woche` reproduziert und
  behoben
- aktuelle Rollenprüfung: q2/q3 führen die Teamleiterinnen-Klassendatei;
  physische q-Homes werden nicht als Queen-Ziele missbraucht
- `koenigin` hat im Klassenkatalog `home_policy: none` und
  `session_policy: logical`; der Runtime-Materialisierungsblocker ist
  reproduzierbar und wird fail-closed ausgegeben
- Queen-Home-Fabrik: 3/3 fokussierte Tests bestanden; zusammen mit
  Queen-/Limittracker-Fokus 9/9 bestanden
- relevante Server-/Fast-Mode-/Spawn-/Queen-Suite: 51 bestanden,
  50 Subtests bestanden
- vollständige Master-Python-Suite: bestanden (Exit-Code 0), einschließlich
  der aktualisierten, vollständigen MCP-Risikokatalog-Prüfung

## Abschluss und bewusste Betriebsgrenze

Dieser Reparaturplan ist abgeschlossen: Anzeige-Datenpfad und Schalter sind
durch die End-to-End-Matrix abgedeckt, die Notfallzustände sind persistent und
idempotent, und die Queen-Home-Fabrik erfüllt den lokalen
Materialisierungs-/Fencing-/Quarantäne-Vertrag. Ein produktiver
Notfall-Queen-Spawn wird **nicht** vorgetäuscht: Solange der Hive deaktiviert
ist und kein kanonischer Queen-Principal samt Runtimeadapter vorhanden ist,
liefert das MCP den dokumentierten Fehler
`queen_spawn_unavailable:hive_queen_runtime_not_materialized`. Die spätere
Adapterveröffentlichung ist ein separates Hive-Enablement-Vorhaben.

## Arbeits-Prompt

```text
Arbeite im codex-usage- und codex-master-Repository am Plan
docs/plans/2026-08-19-notfall-delta-te-aw-und-queen-serienplan.md.

Implementiere noch nichts blind. Reproduziere zuerst den Fehler aus dem
Screenshot mit einem isolierten Testaccount und führe den vollständigen Weg
Backend-DTO -> Payload-Validierung -> Sanitizer -> Normalisierung ->
Fensterselektion -> Targetrouting -> Leiste/Hover/Klick aus. Erweitere die
Diagnostik nur um redigierte Strukturwerte, niemals um Tokens, auth.json,
API-Keys oder Rohterminalausgaben.

Finde zuerst die konkrete Stelle, an der TE-AW oder die Hauptzeile verloren
geht. Prüfe besonders forecast-baseline-enabled, forecast-baseline-minutes,
baseline_used_percent, die getrennte TE-Abfrage, compact/compact-minutes,
Elementtargets, Generationen und Settings-Migration. Ein fehlender AW darf
nicht die ganze TE-Zeile ausblenden. Ein aktivierter Coverage- oder AW-Schalter
darf keine andere Tabelle verändern.

Baue anschließend eine echte End-to-End-Regressionsmatrix. Jede relevante
Kombination aus Leiste/Hover, Coverage, eigenem AW, Bei-null, Delta global,
Targetrouting, Format, Fenster und Emergency-Override muss über den echten
Sanitizer laufen. Prüfe positive und negative Erwartungen sowie Reload und
Resume. Die Matrix muss den bisherigen Fehler reproduzieren, bevor du ihn
behebst.

Implementiere die Reparatur minimal und fail-closed. Der Emergency-Delta darf
nur ein reversibles Overlay sein: War Delta vor dem Notfall aus, muss es nach
dem Ende wieder aus sein. Speichere vorherige Werte nicht durch Überschreiben
der Benutzer-Settings, sondern über einen atomaren, generationsgebundenen
Override.

Implementiere für die Notfall-Queen eine idempotente Lease-Zustandsmaschine.
Zähle ausschließlich laufende, tatsächlich arbeitende Arbeitsbienen; dösende
Gottbienen, Königinnen und Teamleiterinnen zählen nicht. Während eine Queen
oder eines ihrer Kinder einen Plan bearbeitet, darf keine zweite Notfall-Queen
entstehen. Bei aktivem Notfall wird nach vollständigem Planabschluss der
nächste explizit freigegebene bzw. zulässige In-Umsetzung-Plan gewählt. Nach
Notfallende wird kein neuer Plan begonnen; aktueller Plan, Kinder und Queen
beenden sich graceful und hinterlassen ResumeCapsules.

Teste nach jeder Änderung: Syntax, fokussierte Regression, vollständige
Schaltermatrix, Reload/Migration, codex-master Limittracker und die relevante
Server-Suite. Dokumentiere Root Cause, Testlücke, Reparatur, Zustandsmodell,
Rollback und verbleibende Blocker in der Plan-Datei. Melde am Ende exakt,
welche Tests bestanden, welche Dateien geändert und ob eine echte Queen-
Spawn-Primitive vorhanden ist. Wenn sie fehlt, implementiere nicht heimlich
eine Simulation, sondern benenne den Blocker klar.
```
