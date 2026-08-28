# Übergabe externer Markdownpläne

Gilt serverweit für alle verwalteten Bienen und Instanzen.

Wenn ein vollständiger Plan außerhalb des aktuellen Worktrees gespeichert
wird, muss danach ausgeführt werden:

```sh
bin/codex-master-publish-plan-path /absoluter/pfad/zum/plan.md
```

Das Werkzeug prüft die Datei, kopiert nur den vollständigen absoluten Pfad in
die verfügbare Zwischenablage und erzeugt eine variierende
Desktop-Benachrichtigung. Es verwendet `wl-copy`, `xclip` oder `xsel` in dieser
Reihenfolge. Wenn keines verfügbar ist, meldet es einen Fehler und behauptet
nicht, die Übergabe sei erfolgt.

Die Meldung wird bei jedem Aufruf mit echter Zufallsauswahl aus 60
eigenständigen Nachrichtengrundsätzen sowie begrenzten Listen für Anrede,
Einleitung, Nominalformen, Verben und Aktionen erzeugt.
Die Nominalformen enthalten die benötigten Fälle, damit die Kombinationen
auch grammatisch korrekt bleiben. Dadurch entstehen deutlich mehr als 50
verschiedene Nachrichten, ohne dass der Clipboard-Inhalt verändert wird.

Die Regel gilt insbesondere für Obsidian-Vaults, `/Baupläne!` und alle
Dokumente außerhalb des jeweiligen Repository-Worktrees. Der Pfad wird in der
Chatantwort weiterhin als normaler klickbarer Dateilink ausgegeben; der
Zwischenablageinhalt bleibt dagegen frei von Markdown und Zusatztext.
