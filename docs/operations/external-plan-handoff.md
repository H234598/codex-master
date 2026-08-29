# Übergabe externer Markdownpläne

Gilt serverweit für alle verwalteten Bienen und Instanzen.

Wenn ein vollständiger Plan außerhalb des aktuellen Worktrees gespeichert
wird, muss danach ausgeführt werden:

```sh
bin/codex-master-publish-plan-path /absoluter/pfad/zum/plan.md
```

Das Werkzeug prüft die Datei und schreibt den vollständigen validierten
absoluten Markdown-Dateipfad exakt auf stdout. Es liest, entdeckt, verwendet oder
verändert die Zwischenablage nicht; ein bereits vorhandener
Zwischenablageinhalt bleibt unverändert. Zusätzlich erzeugt es eine
variierende sichtbare Desktop-Benachrichtigung, die den vollständigen Pfad
enthält und keine Aussage über Kopieren oder das Ablegen in die Zwischenablage
macht.

Die Meldung wird bei jedem Aufruf mit echter Zufallsauswahl aus 60
eigenständigen Nachrichtengrundsätzen sowie begrenzten Listen für Anrede,
Einleitung, Nominalformen, Verben und Aktionen erzeugt.
Die Nominalformen enthalten die benötigten Fälle, damit die Kombinationen
auch grammatisch korrekt bleiben. Dadurch entstehen deutlich mehr als 50
verschiedene Nachrichten mit dem vollständigen Pfad, ohne dass ein
Clipboard-Inhalt verändert wird.

Die Regel gilt insbesondere für Obsidian-Vaults, `/Baupläne!` und alle
Dokumente außerhalb des jeweiligen Repository-Worktrees. Der Pfad wird in der
Chatantwort weiterhin als normaler klickbarer Dateilink ausgegeben; eine
Clipboard-Aktion findet bei der Übergabe nicht statt.
