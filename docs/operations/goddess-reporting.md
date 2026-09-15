# The Hive Göttinnenberichte

## Verifizierter Quellumfang

Der lokale Server implementiert die Reporting-Oberflächen
`goddess_report_status`, `goddess_report_list` und `goddess_report_run` sowie
die entsprechenden CLI-Unterbefehle `goddess report status`, `run` und `list`.
`run` erzeugt oder ersetzt abhängig von seinen Flags Berichte und ist daher
keine reine Diagnose.

Der eingecheckte User-Service
`systemd/user/the-hive-goddess-report.service` startet den stabilen
The-Hive-Laufzeitlauncher mit `goddess report run`; der passende Timer ist
`systemd/user/the-hive-goddess-report.timer`. Seine Quelle definiert eine
stündliche Auslösung mit bis zu fünf Minuten Zufallsverzögerung. Ob Unit oder
Timer installiert, aktiviert oder erfolgreich gelaufen sind, wurde nicht
abgefragt und ist unbekannt.

## Daten- und Zustandsgrenzen

Berichte verwenden vollständige UTC-Stunden-Buckets. Der private
Reporterzustand ist im Code auf 744 Einträge und 512 KiB begrenzt; ein
Leader-Lock verhindert parallele Läufe. Fehlende oder ungültige
Aufgabenereignisse werden als Datenqualitätsproblem behandelt und dürfen nicht
als erfolgreiche Erledigung ausgelegt werden.

Der Dienst verwendet weiterhin historische technische Zustandskennungen,
einschließlich `CODEX_MASTER_MCP_STATE` und eines gleichnamigen
Standard-Zustandsverzeichnisses. Diese sind Kompatibilitätsverträge, keine
Produktbezeichnung. Ein optionales `CODEX_PROGRAMMING_VAULT` kann den
Berichtsausgabeort bestimmen. Die lokale Status- und Run-Implementierung gibt
einen Vault-Pfad zurück; sie ist daher keine Garantie, dass alle öffentlichen
Reporting-Ausgaben absolute lokale Pfade ausblenden.

## Operative Grenze

Keine Aktivierung, Timerverwaltung oder Berichtserzeugung wird hier
angeordnet. Eine produktive Ausführung schreibt Zustand und gegebenenfalls in
einen Vault und benötigt ein separat autorisiertes Runbook. Der aktuelle
Laufzeit-, Vault- und Reporterpflichtzustand bleibt ohne eine solche Prüfung
unbekannt.
