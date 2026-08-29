# Wiederverwendung der variablen Benachrichtigungssprache

Die 60 Nachrichtengrundsätze des Dokumentübergabe-Werkzeugs sind ein
geeigneter Baustein für kurze, menschlich lesbare Statusmeldungen. Die
Bei der Plan-/Dokumentübergabe werden keinerlei Clipboard-Operationen
ausgeführt.

Sinnvolle abgewandelte Einsatzorte:

- Fast-/Flex-Wechsel: Absender, Account, neuer Modus, Grund und Rückkehrmodus
- Notfallmodus: Aktivierung, regelmäßige Erinnerung, Ende und Wiederherstellung
- Planlebenszyklus: Plan angenommen, gestartet, abgeschlossen, blockiert oder
  zur nächsten Queen-Aufgabe weitergereicht
- Reload/Reinstall: Applet, MCP oder Watchdog erfolgreich neu geladen bzw.
  wegen eines konkreten Fehlers nicht geladen
- Ressourcen- und Modellgate: verständliche Erklärung, welches Limit oder
  welche Modell-/Providerregel den Start verhindert
- ResumeCapsule: Schlafen, Wiederaufnahme, veraltete Generation oder
  erforderliche manuelle Prüfung
- Codex-Usage: Limitfenster erkannt, Warnschwelle erreicht, Monatslimit oder
  Spark-Limit neu bewertet

Dafür sollte später ein gemeinsamer, seitenwirkungsfreier
`notification_phrases`-Baustein die Wortlisten und Grundsätze liefern. Die
jeweiligen Aufrufer setzen ihren Ereignistyp und ihre sicheren Variablen ein;
Geheimnisse, vollständige Payloads und rohe Providerantworten gehören niemals
in die Meldung. Für Statusmeldungen werden keine Clipboard-Operationen
ausgeführt.
