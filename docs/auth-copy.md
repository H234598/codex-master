# The Hive: Authentifizierungsdateien im Pool

## Grenze

`auth.json` ist private, pro Agentin gehaltene Laufzeitinformation. Der
eingecheckte Poolvertrag enthält keine Credentials. Die dort enthaltenen
Codex-Usage-Account-Kennungen bestimmen nur, aus welchem lokalen Profil der
Pool-Installer bei einer fehlenden Zieldatei lesen darf; sie belegen weder eine
vorhandene Anmeldung noch Berechtigung zur Nutzung.

Der aktuelle Installer übernimmt eine fehlende Authentifizierungsdatei als
reguläre private Datei aus dem zugeordneten Profil. Bereits vorhandene
Zieldateien werden nicht ersetzt. Fehlt das erwartete Profil oder ist eine
Quelle nicht regulär und ohne Symlink erreichbar, schlägt die Operation fehl.
Eine aktuelle Verfügbarkeit von Profilen oder Authentifizierungen ist nicht
Teil dieses Dokuments und daher unbekannt.

## Explizite Kopie und Aktualisierung

Die Serveroberfläche enthält `pool copy_auth` und `pool refresh_auth`.
`copy_auth` prüft Quelle, Zielhomes und Selektor; ohne `--yes` bleibt es eine
Vorschau. Mit `--yes` ist es eine Credential-Mutation. `refresh_auth` liest
nur das zur Agentin konfigurierte Profil und verlangt bei einer Ausführung mit
`--yes` einen gestoppten, nicht verwendeten Zielzustand.

Für beide Pfade gilt:

- Quelle und Ziel müssen reguläre Dateien beziehungsweise reale
  Verzeichnisse ohne Symlink sein.
- Vorhandene Zielauthentifizierung bleibt ohne ausdrückliches Überschreiben
  erhalten.
- Antwortdaten enthalten keinen Credential-Inhalt und keinen lokalen Poolpfad.
- Symlinks und Hardlinks für `auth.json` sind kein unterstützter
  Vertrauenspfad.

Diese Seite ist keine Kopierfreigabe. Der eingecheckte
`bin/the-hive-mcp`-Einstiegspunkt benötigt ein attestiertes Release-Binding;
die konfigurierte stabile MCP-Referenz liegt außerhalb des Arbeitsbaums. Eine
produktive Authentifizierungsänderung benötigt daher ein separat autorisiertes
Runbook und aktuelle Quellenprüfung.
