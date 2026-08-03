---
title: Flottenmanagement v2 – Steuerungsarchitektur
project: codex-master
status: approved
created: 2026-08-03
updated: 2026-08-03
source_of_truth: /home/teladi/Dokumente/Obsidian_Vaults/Teladi_Programming/Projekte/codex-master/Baupläne!/Flottenmanagement-v2-Steuerungsarchitektur-Spezifikation.md
---

# Flottenmanagement v2 – Steuerungsarchitektur

Repo-Spiegel der verbindlichen Obsidian-Spezifikation. Inhaltliche Quelle:

`/home/teladi/Dokumente/Obsidian_Vaults/Teladi_Programming/Projekte/codex-master/Baupläne!/Flottenmanagement-v2-Steuerungsarchitektur-Spezifikation.md`

Verbindliche Entscheidungen:

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

Vollständige Architektur, Phasen, Testmatrix und Abnahmekriterien stehen in der
oben genannten Obsidian-Spezifikation.
