# D378-B – Flex-Preiswatchdog: Review-Fix 5 Re-Review Handoff

Stand: 2026-09-27 (Europe/Berlin)
Branch: `d378b-flex-watchdog`
Ausgangs-HEAD: `5de430caa4a8b95d272d3dfb1223cd3b26a9954a`
Abgelehnter Re-Review-Kandidat: `ee59dfc8d0e00da3bf2147785f28997cab29264d`
Review-Fix-5-Re-Review-Änderung: direkte Lead-Session; keine Workerinnen-
Session wurde auf ausdrückliche Anweisung gestartet.

## Ergebnis

Der Inventarlauf nutzt jetzt den kanonischen State-Root
`~/.local/state/the-hive/openai-pricing` und führt genau einen Erstversuch
und höchstens einen Retry aus. Die Pause ist über `run(..., pause=...,
retry_delay_seconds=...)` injizierbar. Bei zwei Fehlschlägen schreibt der
Lauf einen Alert-State und beendet sich mit Exit-Status 1; die Service-Unit
hat keine `Restart=`-Direktive.

`update()` bereitet die neue Generation im Staging vor und stellt bei einem
Fehler nach der Katalog-/Home-Config-Aktualisierung den vorherigen Katalog,
die vorhandenen Config-Dateien, `current` und die bereits veröffentlichte
Generation wieder her. Der Health-State ist davon ausdrücklich ausgenommen:
er dokumentiert den endgültigen Fehler.

Review-Fix 1 ergänzt vier Härtungen:

- `current` wird über eine private eindeutige Tempdatei mit Flush, Datei-Fsync,
  `os.replace()` und anschließendem Fsync der Parent-Directory publiziert.
- Die neu publizierte aktive Generation wird bei der Retention explizit
  übersprungen. Insgesamt werden höchstens 50 Generationen einschließlich
  dieser aktiven Generation behalten, auch wenn die Uhr zurückgestellt ist.
- Der gesamte `run()`-Lauf besitzt einen exklusiven nicht wartenden
  `fcntl.flock`-Lock. Ein Gegenlauf beendet sich mit dem stabilen Code
  `inventory_in_progress`, bevor `update()` oder Artefakte berührt werden.
  Alle Katalog-, Config- und Rollback-Temporärdateien werden eindeutig
  erstellt.
- Beim Lesen der Health-Historie werden nur echte Generationsnamen,
  kanonische timezone-aware ISO-Zeitstempel und bekannte stabile Fehlercodes
  übernommen; untrusted Exception-/Secrettexte werden verworfen.

Review-Fix 2 schließt die verbliebenen Crash-Konsistenzlücken:

- Die Generationsdateien `pricing.html`, `models.html` und `inventory.json`
  werden über die bestehende atomare Hilfsfunktion geschrieben und damit vor
  dem Directory-Rename dateigesynct. Vor dem Rename wird Staging gesynct,
  danach die Root-Directory und erst anschließend `current` dauerhaft
  publiziert.
- Der stabile Katalog ist vor dem Cross-Directory-Rename bereits dateigesynct.
  Nach dem Rename werden Root als Zieldirectory und Staging als Quelldirectory
  gesynct, bevor eine Home-Konfiguration auf den Katalog oder `current` auf
  die neue Generation verweisen kann.

Review-Fix 3 ergänzt eine dauerhafte, wiederholbare Crash-Recovery:

- Vor dem ersten Katalog-/Home-Config-Mutationsschritt wird das private,
  atomar und dateisynct veröffentlichte Journal `.transaction.json` (Schema 1,
  Modus `0600`) angelegt. Es enthält nur eine definierte Phase, neue/alte
  Generationsnamen, Katalog-Existenz und die zwei verwalteten Config-Felder.
  Es enthält weder Geheimnisse noch Rohantworten.
- Ein vorhandener Katalog wird ausschließlich in die private, ebenfalls
  atomar geschriebene `0600`-Backup-Datei gesichert. Nach deren dauerhafter
  Veröffentlichung wird die Journalphase `backup_ready`, erst dann folgen
  Katalog- und Home-Config-Mutationen.
- Jeder Start von `update()` führt die Recovery vor neuen Mutationen aus. Sie
  stellt `current`, Katalog und nur die verwalteten Config-Felder her, entfernt
  neue Generation/Staging und entfernt Journal erst durable nach vollständiger
  Wiederherstellung. Wiederholung ist idempotent. Die genaue Finalisierungs-
  und Backup-Entfernungsreihenfolge ist unter Review-Fix 4 dokumentiert.
- Das Cleanup-Ziel der neuen Generation wird direkt nach erfolgreichem
  `staging.rename()` und vor dem Root-Fsync registriert. Ein Fsync-Fehler an
  dieser Stelle räumt die noch nicht publizierte Generation wieder auf.

Review-Fix 4 schließt Transaktionsfinalisierung und Config-Journal weiter:

- Die Transaktion wird nach dauerhafter `current`-Publikation zuerst mit
  `committed` atomar markiert. Ihr Backup wird durable entfernt und das Journal
  erst anschließend, ebenfalls durable, entfernt. Erst danach beginnt die
  destruktive Retention. Damit kann kein Retention-Abbruch eine noch für
  Recovery benötigte vorherige Current-Generation löschen.
- Eine unterbrochene Rücknahme markiert nach vollständiger Wiederherstellung
  `rolled_back`; sowohl diese als auch eine `committed`-Transaktion entfernt
  bei jedem Start erst Backup und zuletzt Journal. Cleanup-Fehler bleiben
  sichtbar und ein weiterer Start wiederholt nur den idempotenten Cleanup,
  ohne einen erfolgreich committeten Zustand zurückzudrehen.
- Das Journal enthält keine Rohzeilen aus Home-Konfigurationen mehr, sondern
  nur normalisierte semantische Objekte `{index, key, value}`. Erlaubt sind
  nur die im Repository belegten Tiers `auto`, `flex`, `priority` sowie ein
  lokaler absoluter `model_catalog_json`-Pfad ohne Steuerzeichen, Kommentar
  oder zusätzliche TOML-Tokens. Ungültige oder mehrdeutige Homes werden vor
  Mutation übersprungen und erscheinen weder im Journal noch im Inventar.

Review-Fix 5 härtet `model_catalog_json` als Journalwert weiter:

- Akzeptiert werden ausschließlich bereits normalisierte lokale absolute
  Dateisystempfade. Lexische Traversal-/Punktkomponenten, doppelte
  Wurzelpräfixe, Steuerzeichen, Backslashes sowie Query-/Fragment-Zeichen
  werden verworfen.
- Verworfen werden ausschließlich strukturelle Credential-Zuweisungen: ein
  abgegrenzter Credential-Feldname (zum Beispiel API-Key oder Token), direkt
  gefolgt von `=` oder `:` und einem nichtleeren Wert. Bloße Feldnamen und
  normale Pfadkomponenten wie `author`, `authentication` oder
  `secret-catalog` bleiben gültig. Der abgelehnte Wert erscheint weder im
  wertfreien Parserfehler noch in Journal oder Inventar; die Update-Planung
  überspringt das betreffende Home.
- Jeder bereits existierende Pfadbestandteil wird mit `lstat` geprüft.
  Symlinks oder nicht prüfbare Bestandteile führen zur Verwerfung; der finale
  Katalog darf für den ersten Lauf weiterhin noch nicht existieren.

## Health-State

Pfad: `~/.local/state/the-hive/openai-pricing/health.json`.

Das JSON enthält nur `schema_version`, `status` (`healthy` oder `alert`),
`updated_at`, `attempts` sowie – soweit vorhanden –
`last_successful_generation`, `last_successful_at`, `last_error_at` und
`last_error_code`. Fehler werden als stabile Codes (`invalid_response`,
`io_error`, `inventory_failed`, `inventory_in_progress`) abgelegt. Weder
Geheimnisse, Rohantworten noch Exception-Texte werden serialisiert.

Der State wird in derselben Directory in eine exklusiv erzeugte temporäre
Datei mit Modus `0600` geschrieben, geflusht, dateigesynct und mit
`os.replace()` atomar veröffentlicht; danach wird die Parent-Directory
gesynct. Der Root wird auf `0700` gesetzt. Ein erfolgreicher Lauf setzt
`healthy` und übernimmt vorhandene letzte Fehlerzeit/-codes.

## Units und Entrypoint

- Service: `the-hive-openai-pricing.service`, `Type=oneshot`, The-Hive-
  Entrypoint und `ReadWritePaths=%h/.local/state/the-hive/openai-pricing`.
- Timer: täglich (`OnCalendar=daily`), persistent und an dieselbe The-Hive-
  Service-Unit gebunden.
- Der Service besitzt weiterhin `ProtectHome=no`, weil der bestehende
  Inventarvertrag bei Erfolg vorhandene Codex-Home-Konfigurationen und
  -Kataloge aktualisiert. Dies wurde nicht zur Laufzeit mit einem
  installierten systemd-Manager geprüft.

## Geänderte Dateien

- `src/the_hive/pricing_inventory.py`
- `tests/test_pricing_inventory.py`
- `systemd/user/the-hive-openai-pricing.service`
- `systemd/user/the-hive-openai-pricing.timer`
- dieser Handoff

Die vorgefundene unversionierte Datei `uv.lock` wurde entfernt. Der Entrypoint
`bin/the-hive-openai-pricing-inventory` wurde geprüft und benötigt keine
Änderung.

## Nachweise

Vor der Bearbeitung: Branch `d378b-flex-watchdog`, Ausgangs-HEAD wie oben,
keine versionierten Diff-Änderungen; ausschließlich `uv.lock` war
unversioniert vorhanden.

Die Lead-Session hat nach Integration selbst erfolgreich ausgeführt:

```
PYTHONPATH=src python3 -m pytest -q tests/test_pricing_inventory.py
# 31 passed in 1.36s
python3 -m py_compile src/the_hive/pricing_inventory.py
git diff --check HEAD^ HEAD
```

Die Regressionsfälle umfassen den Datei- und Directory-Fsync bei `current`,
50 lexikographisch neuere Generationen bei zurückgestellter Uhr, einen
Gegenlauf ohne Artefaktänderung, eindeutige Config-/Rollback-Temps sowie
valide und ungültige Health-Historie. Review-Fix 2 ergänzt fokussierte
Ereignisfolgen für Generationsdatei-Fsync → Staging-Fsync → Rename →
Root-Fsync → `current` sowie Katalogdatei-Fsync → Cross-Directory-Rename →
Ziel-/Quell-Directory-Fsync → Home-Config/`current`.

Review-Fix 3 ergänzt simulierte Prozessabbrüche nach Config- und nach
`current`-Mutation, jeweils mit zweimaliger Start-Recovery; der Journalinhalt
wird dabei auf Abwesenheit eines Config-Secrets und einer Rohantwort geprüft.
Ein separater Fall injiziert den Root-Fsync-Fehler unmittelbar nach dem
Generationsrename und belegt das Cleanup ohne Staging-/Target-Rest.

Review-Fix 4 ergänzt einen harten Retention-Abbruch mit lexikografisch
ältester vorheriger Current-Generation bei mehr als 50 Generationen,
bösartige TOML-Zeilen ohne Journal-/Inventar-Leak sowie fehlgeschlagenes
Backup-Cleanup mit erfolgreichem zweiten Lauf.

Review-Fix 5 ergänzt fokussierte Tests für Traversal, einen existierenden
Parent-Symlink, Query-/Secret- und Steuerzeichenwerte, einen gültigen noch
nicht existierenden Erstlaufpfad sowie die Abwesenheit des verworfenen Werts
aus Journal, Inventar und Fehlertext. Der Re-Review ergänzt legitime
normalisierte Pfade mit `author`, `authentication`, `secret-catalog` und
einem Credential-Feldnamen ohne Wert, neben einer tatsächlich strukturierten
Credential-Zuweisung mit `=` oder `:`.

Kein Volltestlauf, keine Installation, kein Push und kein MCP-Aufruf wurden
ausgeführt. Remote-OpenAI-Antworten und die Aktivierung durch einen realen
systemd-User-Manager wurden bewusst nicht geprüft; hierfür liegt keine
Ausführungsevidenz vor.

## Integration

Die direkte Review-Fix-5-Änderung und dieser Handoff werden per
`git commit --amend` in genau einem sauberen Branch-Commit integriert. Die
endgültige Commit-ID ist im Abschlussprotokoll der Lead-Session per
`git rev-parse HEAD` ausgewiesen; sie kann nicht sinnvoll selbstreferenziell
in den Inhalt dieses Commits aufgenommen werden.
