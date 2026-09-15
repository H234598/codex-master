# The Hive Enforced-Pilot-Provisioner

## Verifizierter Quellumfang

Der einzige eingecheckte Wrapper heißt
`scripts/the-hive-hive-pilot-provisioner`; er startet
`the_hive.hive.pilot_provisioner`. Der Parser bietet `plan`, `verify`,
`apply`, `rollback` und `kill-switch`. Die letzten drei verlangen eine
explizite Bestätigung und verändern lokale Pilotdateien oder -zustände. Diese
Dokumentation enthält deshalb keine ausführbaren Provisionierungs- oder
Rollback-Schritte.

Der Quellvertrag begrenzt diesen Piloten auf genau eine Repository-Bindung und
zwei Principals. In der eingecheckten `codex-hive.json` tragen diese
technischen, historischen Kompatibilitätskennungen noch `codex-master`; sie
sind keine Produktbezeichnung von The Hive. Die Datei setzt den Modus auf
`enforced` und alle SP-Flags auf `false`.

## Blockierende Gates

Die Runtime prüft Config-, Principal-, Repository- und State-Evidenz und
verlangt zusätzlich eine gültige Pilot-Account-Attestierung. Der vorliegende
Quellstand liefert dafür keine positive Attestierung; der Gate-Pfad bleibt
fail-closed. Reale externe Freigaben, Provider-Credentials, die aktuelle
Repository-Arbeitskopie und ein produktiver Pilotzustand wurden nicht
ausgeführt oder geprüft und sind unbekannt.

Auch eine logische Königin ist nicht materialisiert. Der bekannte
Emergency-Pfad meldet hierfür
`queen_spawn_unavailable:hive_queen_runtime_not_materialized`.

## Handlungsgrenze

Plan-, Apply-, Kill-Switch- und Rollback-Operationen sind Verwaltungsaktionen
mit privatem Zustand. Sie dürfen nur über ein separat autorisiertes Runbook
und nach aktueller Evidenzprüfung erfolgen; weder dieses Dokument noch eine
vorhandene Konfigurationsdatei ist eine solche Freigabe.
