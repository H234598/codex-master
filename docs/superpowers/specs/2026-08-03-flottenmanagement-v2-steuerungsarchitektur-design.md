---
title: Flottenmanagement v2 – Steuerungsarchitektur
project: codex-master
status: approved
created: 2026-08-03
updated: 2026-08-08
implementation_status: P3/P3a source-complete; live deployment pending
source_of_truth: /home/teladi/Dokumente/Obsidian_Vaults/Teladi_Programming/Projekte/codex-master/Baupläne!/Flottenmanagement-v2-Steuerungsarchitektur-Spezifikation.md
---

# Flottenmanagement v2 – Steuerungsarchitektur

Repo-Spiegel der verbindlichen Obsidian-Spezifikation. Inhaltliche Quelle:

`/home/teladi/Dokumente/Obsidian_Vaults/Teladi_Programming/Projekte/codex-master/Baupläne!/Flottenmanagement-v2-Steuerungsarchitektur-Spezifikation.md`

Verbindliche Entscheidungen:

- Das Projekt wird kanonisch **The Hive** genannt. `codex-master-mcp`,
  `codex-master` und umgangssprachlich `Masterjet` bleiben gültige Aliase;
  bestehende CLI-/MCP-Registrierungen müssen deshalb nicht sofort umbenannt
  werden.
- Die Fleet Registry ist die einzige Laufzeitquelle für alle Serien,
  einschließlich der nativen Serien A/B/C. Skill-Projektionen werden je
  Klassenprofil materialisiert; identische Klassen sehen identische Skills,
  gesperrte oder gefährliche Skills werden nicht projiziert.

- Cinnamon-Applet zeigt alle aktiven verwalteten Bienen und erlaubt nur
  Einzelstart, Einzelstop, Refresh und Öffnen der Steuerzentrale.
- Native Codex-Subagentinnen erscheinen in einem getrennten, fest auf sechs
  wiederverwendbare Zeilen begrenzten Untermenü. Sie bleiben im Applet
  read-only und werden nie mit tmux-Bienen vermischt.
- Offizielle `SessionStart`-/`SubagentStart`-/`SubagentStop`-/
  `SessionEnd`-Hooks pflegen ein
  privates, auf 64 Einträge und 64 KiB begrenztes Native-Register. Prompts,
  Antworten, Transkriptpfade und Terminaldaten werden weder gelesen noch
  gespeichert; Hookfehler dürfen Codex nicht blockieren.
- Eigenständige GTK-3.24-Steuerzentrale bietet Teamleiterinnen sämtliche
  freigegebenen strukturierten Flottenfunktionen.
- Vollständige MCP-Tools sind ausschließlich explizit lokal registrierten
  Teamleiterinnen sichtbar und auch bei `tools/call` rollenautorisiert.
- `codex-usage.backend_account_id` gruppiert gemeinsam authentifizierte Bienen.
  Ein erreichtes Accountlimit sperrt jede Gruppenbiene bis zum bestätigten
  Reset und entfernt sie aus allen Start-/Spawn-Angeboten.
- Applet bleibt auf einen asynchronen, begrenzten Backendprozess beschränkt.
- App Server ist nur optionale Native-Live-Ergänzung; Session-JSONL und
  Transkripte sind keine Statusquelle.
- GTK läuft separat, ohne Netzwerklistener, und blockiert weder Cinnamon noch
  seinen eigenen Mainloop.
- Vollständig meint jedes extern freigegebene Teamleiterinnen-Tool aus
  `tools/list`; interne CLI-Helfer bleiben ausgeschlossen. Neue unbekannte
  Tools sind bis zur Risikoklassifizierung nicht mutierbar.
- Umsetzung wird in getrennte, jeweils test- und rückrollbare Meilensteinpläne
  zerlegt.
- Stabilität > Security > Performance.

## Belegter P3/P3a-Stand

- Vertrag 1 bleibt für alte Aufrufer verfügbar. Das Cinnamon-Applet fordert
  ausdrücklich Vertrag 2 an.
- Vertrag 2 inventarisiert bekannte laufende tmux-Bienen einmal pro Refresh
  automatisch. Angeheftete schlafende Bienen füllen nur freie der sechs festen
  Zeilen; Inventurfehler fallen nicht auf `a1,b1` als angebliche Flotte zurück.
- Native Bienen laufen über das private, atomar geschriebene und begrenzte
  Register. Hook-State und UI enthalten keine Prompts, Antworten,
  Transkriptpfade oder Terminaldaten.
- Verwaltete und Native-Bienen bleiben in Vertrag und Applet getrennt. Das
  Native-Untermenü besitzt sechs einmal erzeugte Zeilen; 500 Refreshes und 100
  Load-/Unload-Zyklen behalten feste Objekt- und Ressourcenobergrenzen.
- Hookfehler sind zeitbegrenzt und können Codex-Lifecycle-Ereignisse nicht
  blockieren. Symlink-, Hardlink-, Größen-, Lock-, Zeit- und kaputte
  State-Fälle sind verhaltensgetestet.
- Plugin-Sync übernimmt die regulären Dateien `hooks/hooks.json` und
  `hooks/native_bee_event.py`. Der Applet-Installer verweigert unsichere
  Dateitypen und Identitätswechsel; atomare Installation und Rollback bleiben
  direkt getestet.

Damit sind Source- und automatisierte Testgates für P3/P3a erfüllt. Reale
Cinnamon-Anzeige und Codex-Hookvertrauen bleiben externe Deploymentgates; ohne
diese Handlungen ist keine Live-Abnahme behauptet.

## Deployment- und Vertrauensgate

```sh
./bin/codex-master-mcp install
./scripts/codex-master-cinnamon-applet install
./scripts/codex-master-cinnamon-applet verify
```

Danach muss eine neue Codex-Sitzung geöffnet werden. Dort `/hooks` ausführen,
die vier Plugin-Hookdefinitionen prüfen und ausdrücklich manuell vertrauen.
Kein Installer und kein Test manipuliert Hook-Trust-State oder behauptet einen
Trust-Automatismus.

Abschluss in realer Cinnamon-Sitzung: Titel `Flottenmanagement`, alle regulär
aktiven verwalteten Bienen, getrenntes Untermenü `Native Bienen`, keine neuen
kritischen Journalmeldungen. Echte Nutzerinstallation und Vertrauenshandlung
erfolgen erst nach Review durch Controller.

Vollständige Architektur, Phasen, Testmatrix und Abnahmekriterien stehen in der
oben genannten Obsidian-Spezifikation.
