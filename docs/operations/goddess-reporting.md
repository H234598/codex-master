# Göttinnenberichte und Flottenübersicht

Dieses Dokument beschreibt den kanonischen Reportingpfad von `codex-master`.
Applet, CLI und MCP greifen auf dieselbe Fleet-Overview-Struktur zu. Rohprompts,
Rohantworten, API-Keys, Credential-Fingerprints und lokale Arbeitsverzeichnisse
gehören nicht in öffentliche Overview- oder Reportausgaben.

## Flottenübersicht

CLI:

```sh
./bin/codex-master-mcp fleet overview
./bin/codex-master-mcp fleet overview --format json
./bin/codex-master-mcp fleet overview --no-active-only --format markdown
```

MCP stellt dieselbe Information über `fleet_overview` bereit. `format=json`
liefert strukturierte Daten; `format=compact` liefert die kurze Tabelle. Das
optionale `include_limits=false` blendet Limit- und Stundenkostenfelder aus.
`fleet_status_compact` ist der kurze Statuspfad für Statusfragen. Er listet
standardmäßig nur aktive Bienen.

Limitwerte kommen ausschließlich aus dem `codex-usage`-Vertrag. Fehlende,
veraltete oder nicht lesbare Werte bleiben unbekannt (`—`/`unavailable`) und
werden nicht als Null interpretiert. Öffentliche Gemini-Zeilen zeigen Account-ID
oder Label, aber nie Schlüsselmaterial oder Fingerprints.

## G-Serie

Die Registry-v2 führt eine logische Serie `g`/`G-Serie` mit einzelnen
Mitgliedern. Jedes aktive Gemini-Mitglied bindet genau einen Account. Die
Credential-Bindung wird intern geprüft; öffentliche Snapshots, Tabellen und
Reports geben sie nicht aus. Ein Credential darf höchstens an eine aktive
Gemini-Biene gebunden sein. Migrationen erhalten Alias- und Journalinformationen
und legen doppelte Bienen kontrolliert still, statt sie ungeprüft zu löschen.

Spawn, Recovery, Import und manuelle Serienänderung müssen dieselbe
Credential-Eindeutigkeitsprüfung erfüllen. Ein fehlendes Credential blockiert
Aktivierung mit einem generischen Fehlerzustand.

## Reporter-Invariante

Eine Göttinnenbiene ist nur dann reporterpflichtig, wenn beides gilt:

1. aktiver Principal mit Root-Executive-Rolle `goettin` oder `goddess`;
2. aktive, nicht abgelaufene Execution Binding.

Ein bloßer Prompt oder ein historischer Principal aktiviert keinen Reporter.
Der Supervisor verwendet einen kernelbasierten exklusiven Lock. Höchstens ein
Prozess besitzt `leader.lock`; abgestürzte Prozesse geben den Lock durch
Kernelfreigabe frei. Status prüft den Lock, ohne ihn zu übernehmen. Fehlt der
Leader trotz bestehender Reporterpflicht, ist der Status `degraded`.

Reporterzustand liegt privat unter:

```text
~/.local/state/codex-master-mcp/goddess-reporter/
  state.json       # Bucket-Metadaten, Hashes, Retryzähler
  leader.lock      # exklusiver Prozess-Lock
```

Der Hive hält zusätzlich unter `~/.local/state/codex-master-mcp/hive/events.jsonl`
einen privaten, gesperrten und auf 4096 Datensätze/512 KiB begrenzten Eventpuffer.
Er enthält nur Assignment-/Queue-/Completion-Metadaten und niemals Payloads,
Prompts, Antworten oder Credentials.

`state.json` bleibt auf 744 Bucketdatensätze und 512 KiB begrenzt. Datei und
Elternverzeichnis werden privat angelegt; Zustand wird atomar ersetzt. Pro
Bucket wird SHA-256 des kanonischen Markdown gespeichert. Gleicher Inhalt ist
idempotent. Anderer finaler Inhalt braucht explizit `replace=true` bzw.
`--replace`.

## UTC-Buckets und Nachholung

Ein Bucket ist eine abgeschlossene UTC-Stunde mit ID
`YYYY-MM-DDTHH:00:00Z/PT1H`. Standardmäßig wird er fünf Minuten nach
Stundenende fällig. Die Nachholung läuft chronologisch und umfasst höchstens 24
Stunden. Ein partieller Bericht trägt `status: partial`; ein abgeschlossener
Bericht trägt `status: final`.

Fehlende Usage-, Task- oder Bindingdaten verhindern die Berichtserzeugung nicht.
Sie erscheinen als Datenqualitäts- oder Risikoangabe. Taskzeilen werden aus dem
privaten Assignment-Log, dem Gemini-Result-Eventlog und dem Hive-Eventpuffer
abgeleitet. Assignment-IDs dienen als Titel, weil Prompts und Antworten nicht
persistiert oder ausgegeben werden. Ohne Abschlussereignis bleibt ein Auftrag
offen; eine vollständige Erledigtenliste wird daraus nicht abgeleitet.

## CLI

```sh
./bin/codex-master-mcp goddess report status
./bin/codex-master-mcp goddess report run
./bin/codex-master-mcp goddess report run --bucket-start 2026-08-16T10:00:00Z
./bin/codex-master-mcp goddess report list --limit 24
./bin/codex-master-mcp goddess report list \
  --from 2026-08-16T00:00:00Z --to 2026-08-16T23:00:00Z
```

CLI-Antworten sind JSON und datenarm. `run` enthält den sanitisierten
Markdown-Bericht sowie Bucket-, Vault- und Zustandsmarker. `list` gibt nur
begrenzte Bucketmetadaten aus. Ungültige Zeitstempel, umgekehrte Zeitbereiche,
unbeschreibbare Vaults und belegte Leader-Locks schlagen geschlossen mit einem
generischen Fehlercode fehl.

Ohne `--bucket-start` verarbeitet `run` alle fälligen UTC-Buckets chronologisch
seit dem letzten finalen Bucket, höchstens 24 Stunden rückwirkend. Ein
fehlgeschlagener Bucket wird nicht als final markiert und wird beim nächsten
Lauf erneut versucht. Der explizite Bucket-Aufruf bleibt auf genau einen
Bucket begrenzt.

Für automatische Ausführung:

```sh
systemctl --user daemon-reload
systemctl --user enable --now codex-master-goddess-report.timer
systemctl --user status codex-master-goddess-report.timer
```

Der Timer startet den gehärteten User-Service stündlich mit bis zu fünf Minuten
Jitter. Der Service schreibt ausschließlich in den Master-State und den
konfigurierten Default-Vault; der Reporter-Leader-Lock verhindert parallele
Läufe.

## Vault-Ausgabe

Der Default-Vault ist:

```text
~/Dokumente/Obsidian_Vaults/Teladi_Programming
```

`CODEX_PROGRAMMING_VAULT` darf einen absoluten alternativen Vault setzen. Der
Writer legt fehlende Verzeichnisse automatisch an, lehnt Symlink-Ancestors und
Nicht-Regular-Dateien ab und schreibt über eine private temporäre Datei mit
`fsync` und atomarem Replace. Ein vorhandener finaler Bericht wird nicht
überschrieben, außer `replace` ist ausdrücklich gesetzt.

## MCP-Werkzeuge

| Werkzeug | Risiko | Zweck |
|---|---|---|
| `fleet_overview` | read-only | kanonische Übersicht, JSON oder kompakt |
| `fleet_status_compact` | read-only | kurze aktive Statusantwort |
| `goddess_report_status` | read-only | Reporterpflicht, Leader, Bucket- und Fehlerstatus |
| `goddess_report_list` | read-only | begrenzte Bucketmetadaten |
| `goddess_report_run` | mutating | einen Bucket erzeugen; final immutable |

Die Werkzeuge haben geschlossene Schemas. Unbekannte Felder, falsche Typen und
ungültige Grenzen werden vor der Ausführung abgelehnt. Risiko-Katalog und
Tooldefinition müssen gemeinsam gepflegt werden.

## Noch offene Ausbaustufen

Der aktuelle Pfad besitzt Registry-/Overview-/Usage-Vertrag, sicheren Writer,
Assignment-/Result-/Hive-Taskaggregation, Bucket-State, Single-Leader-Lock,
CLI/MCP-Grundpfad und stündliche Timer-/Backfill-/Retry-Anbindung. Der
Eventpuffer bleibt absichtlich ein expliziter Producer-Vertrag: reine Hive-
Statusmaschinen erzeugen keine versteckten Dateiseiteneffekte. Der serverseitige
Queen-Adapter kann einen `HiveEventStore` erhalten und schreibt dann Queue-
Start und Abschlussstatus. Nicht angeschlossene Producer bleiben als fehlende
Abschlussereignisse sichtbar.
