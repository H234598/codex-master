# The Hive Agentinnen-Pool

## Geltungsbereich und Status

Der Agentinnen-Pool ist eine lokale, schlafende The-Hive-Flotte. Der
eingecheckte Poolvertrag liegt in `codex-agent-pool.json`; er beschreibt
Agentinnen, Selektoren, gemeinsame Assets, private Laufzeitverzeichnisse und
die erwartete Codex-CLI. Er ist weder ein Secret Store noch ein Nachweis, dass
eine lokale Flotte installiert, authentifiziert oder gestartet ist.

Die aktuelle Beispieldatei enthält die Serien `a`, `b`, `c` und `u`. Ihr
konkreter Laufzeit- und Authentifizierungszustand wurde für diese
Dokumentation nicht abgefragt und bleibt daher unbekannt.

## Verifizierte Schnittstellengrenze

`bin/the-hive-mcp` ist ein Release-Einstiegspunkt, kein direkt nutzbarer
Entwicklungs-Wrapper: Er verlangt Release-Root, Generation und
Manifest-Digest. Die eingecheckte MCP-Konfiguration referenziert stattdessen
den deployment-konfigurierten stabilen lokalen Launcher. Ob dieses installierte
Release vorhanden oder gültig ist, ist hier nicht nachgewiesen.

Der Parser des The-Hive-Servers führt die Pool-Unterbefehle `validate`,
`install`, `status`, `copy_auth`, `refresh_auth` und `destroy_pool`. Die
Unterbefehle mit einer Bestätigung (`--yes`) können private Dateien verändern
oder entfernen. `scripts/install-agent-pool` ruft ebenfalls `pool install`
über ein installiertes Release auf und ist keine Diagnose oder sichere
Vorschau. Diese Seite gibt deshalb keine auszuführende Installations-,
Kopier- oder Löschsequenz vor.

## Konfigurations- und Vertrauensmodell

- Der Pool-Parser akzeptiert nur einen begrenzten, nicht-symlinkten Poolroot
  und reguläre, private Homes, Wrapper und Konfigurationsdateien.
- `pool install` erstellt Homes, Wrapper, Minimal-Konfigurationen und
  Laufzeitverzeichnisse. Es startet keine Agentin.
- Fehlende `auth.json`-Dateien werden beim Installieren nur aus dem für die
  Agentin konfigurierten lokalen Codex-Usage-Profil übernommen; vorhandene
  Zieldateien bleiben erhalten. Eine nicht verfügbare Quelle blockiert die
  Operation. Der tatsächliche Zustand dieser Quellen ist unbekannt.
- Gemeinsame Assets sind ein gesonderter, geprüfter Link-Mechanismus. Für
  `auth.json` sind Symlinks und Hardlinks kein unterstütztes Modell.
- Arbeitsmutationen verlangen standardmäßig eine reguläre lokale
  `auth.json`; eine ausdrückliche unauthentifizierte Ausnahme ist nur für
  Login- oder Bootstrap-Flüsse vorgesehen.

Öffentliche Poolantworten sind datenarm und geben weder Authentifizierungsinhalt
noch Poolroot zurück. Historische Namen in privaten Zustands- oder
Umgebungsverträgen sind technische Kompatibilitätsbezeichner und keine
Produktbezeichnung.

## Operative Grenze

Vor jeder tatsächlichen Poolmutation müssen ein autorisiertes Runbook, die
Gültigkeit des installierten Release und die verfügbaren Authentifizierungs-
Quellen separat belegt werden. Diese Nachweise sowie eine produktive
Provisionierung liegen außerhalb dieses Repository-Dokuments.
